"""
Mandiant Public Reports Ingestion
Mandiant publishes detailed threat intelligence reports with actor names, industries, and techniques
URL: https://www.mandiant.com/resources/reports
"""
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, date
from typing import Dict, List
import re

from app.models import Source
from app.services.ingestion.normalizer import Normalizer
from app.services.matcher import extract_technique_ids
from app.services.ingestion.enhanced_extraction import (
    extract_actors_enhanced, extract_industries_enhanced, extract_techniques_enhanced
)
from app.utils.logging import setup_logging

logger = setup_logging()

MANDIANT_BASE_URL = "https://www.mandiant.com"
# Mandiant was acquired by Google - try both URLs
MANDIANT_REPORTS_URL = f"{MANDIANT_BASE_URL}/resources/reports"
GOOGLE_CLOUD_SECURITY_URL = "https://cloud.google.com/security/resources"
MANDIANT_SITEMAP_URL = f"{MANDIANT_BASE_URL}/sitemap.xml"


class MandiantIngester:
    """Ingest data from Mandiant public reports"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
    
    async def ingest(self, limit: int = 20) -> Dict[str, int]:
        """
        Ingest Mandiant reports
        Returns stats: {reports_processed, evidence_created}
        """
        logger.info("Starting Mandiant reports ingestion")
        
        # Get or create Mandiant source
        source = await self._get_or_create_source()
        
        stats = {
            "reports_processed": 0,
            "evidence_created": 0
        }
        
        # Try sitemap first (most reliable)
        report_links = []
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                # Try main sitemap
                response = await client.get(MANDIANT_SITEMAP_URL)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "xml")
                    
                    # Check for nested sitemaps first
                    nested_sitemaps = soup.find_all("sitemap")
                    if nested_sitemaps:
                        logger.info(f"Found {len(nested_sitemaps)} nested sitemaps, checking them...")
                        for sitemap_elem in nested_sitemaps:
                            loc = sitemap_elem.find("loc")
                            if loc:
                                nested_url = loc.text.strip()
                                try:
                                    nested_resp = await client.get(nested_url, timeout=10.0)
                                    if nested_resp.status_code == 200:
                                        nested_soup = BeautifulSoup(nested_resp.text, "xml")
                                        nested_urls = nested_soup.find_all("url")
                                        for url_elem in nested_urls:
                                            url_loc = url_elem.find("loc")
                                            if url_loc:
                                                url_text = url_loc.text.strip()
                                                # Filter to English reports only (avoid duplicates from translations)
                                                if "/resources/reports/" in url_text and "mandiant.com/resources/reports" in url_text:
                                                    if url_text not in report_links:
                                                        report_links.append(url_text)
                                except Exception as e:
                                    logger.warning(f"Failed to fetch nested sitemap {nested_url}: {e}")
                    
                    # Also check direct URLs in main sitemap
                    urls = soup.find_all("url")
                    for url_elem in urls:
                        loc = url_elem.find("loc")
                        if loc:
                            url_text = loc.text.strip()
                            if "/resources/reports/" in url_text and url_text not in report_links:
                                report_links.append(url_text)
                    
                    logger.info(f"Found {len(report_links)} report URLs from sitemap(s)")
            except Exception as e:
                logger.warning(f"Sitemap fetch failed: {e}")
            
            # Fallback to HTML scraping if sitemap didn't work
            if not report_links:
                try:
                    response = await client.get(MANDIANT_REPORTS_URL)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, "lxml")
                    
                    # Try multiple selectors
                    selectors = [
                        "article a[href*='/resources/reports/']",
                        ".report-card a",
                        ".resource-item a",
                        "a[href*='mandiant.com/resources/reports']",
                        "a[href*='/resources/reports']"
                    ]
                    
                    for selector in selectors:
                        links = soup.select(selector)
                        for link in links:
                            href = link.get("href", "")
                            if href and "/resources/reports/" in href:
                                if href.startswith("/"):
                                    url = f"{MANDIANT_BASE_URL}{href}"
                                elif href.startswith("http"):
                                    url = href
                                else:
                                    continue
                                
                                if url not in report_links:
                                    report_links.append(url)
                except Exception as e:
                    logger.warning(f"HTML scraping fallback failed: {e}")
            
            if not report_links:
                logger.error("Failed to find any report links")
                return {"error": "No report links found"}
        
        # Now process reports in a new client session (to keep it open)
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            # Process reports (client stays open for all requests)
            for url in report_links[:limit]:
                try:
                    evidence_count = await self._process_report(url, source, client)
                    if evidence_count > 0:
                        stats["reports_processed"] += 1
                        stats["evidence_created"] += evidence_count
                except Exception as e:
                    logger.error(f"Error processing report {url}: {e}")
                    continue
        
        # Update source last_checked_at
        source.last_checked_at = date.today()
        await self.db.commit()
        
        logger.info(f"Mandiant ingestion complete: {stats}")
        return stats
    
    async def _get_or_create_source(self) -> Source:
        """Get or create Mandiant source"""
        result = await self.db.execute(
            select(Source).where(Source.name == "Mandiant Report")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            from config import settings
            source = Source(
                name="Mandiant Report",
                type="report",
                base_url=MANDIANT_BASE_URL,
                reliability_score=9,  # High reliability
                meta_data={"reports_url": MANDIANT_REPORTS_URL}
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
    
    async def _process_report(
        self,
        url: str,
        source: Source,
        client: httpx.AsyncClient
    ) -> int:
        """Process a single Mandiant report"""
        try:
            response = await client.get(url, timeout=15.0)
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return 0
        
        soup = BeautifulSoup(response.text, "lxml")
        
        # Extract title
        title_elem = soup.select_one("h1, .page-title, title, .report-title")
        title = title_elem.get_text(strip=True) if title_elem else "Mandiant Report"
        
        # Extract date
        date_elem = soup.select_one("time, .date, .published-date, .report-date")
        source_date = date.today()
        if date_elem:
            date_text = date_elem.get_text(strip=True)
            try:
                from dateutil import parser
                source_date = parser.parse(date_text).date()
            except:
                pass
        
        # Extract text content
        content_elem = soup.select_one("article, .content, .body, main, .report-content")
        if not content_elem:
            content_elem = soup
        
        text = content_elem.get_text(separator=" ", strip=True)
        
        # Extract actor names (use enhanced extraction)
        actors = extract_actors_enhanced(text, title)
        if not actors:
            actors = self._extract_actors(text)
        
        # Extract industry keywords (use enhanced extraction)
        industries = extract_industries_enhanced(text, title)
        if industries:
            industry_text = " ".join(industries)
        else:
            industry_text = self._extract_industry_context(text, title)
        
        # Extract technique IDs (use enhanced extraction)
        technique_ids = extract_techniques_enhanced(text)
        if not technique_ids:
            technique_ids = extract_technique_ids(text)
        
        # Create evidence items
        evidence_count = 0
        for actor_name in actors:
            items = await self.normalizer.create_evidence_item(
                actor_name=actor_name,
                source=source,
                source_url=url,
                source_title=title,
                source_date=source_date,
                industry_keywords=industry_text,
                technique_ids=technique_ids if technique_ids else None,
                excerpt=text[:500] if len(text) > 500 else text
            )
            evidence_count += len(items)
        
        return evidence_count
    
    def _extract_actors(self, text: str) -> List[str]:
        """Extract threat actor names from text"""
        actors = []
        
        # Known APT groups and threat actors
        known_actors = [
            "APT1", "APT2", "APT3", "APT4", "APT5", "APT6", "APT7", "APT8", "APT9", "APT10",
            "APT12", "APT16", "APT17", "APT18", "APT19", "APT20", "APT21", "APT22", "APT23",
            "APT27", "APT28", "APT29", "APT30", "APT31", "APT32", "APT33", "APT34", "APT35",
            "APT36", "APT37", "APT38", "APT39", "APT40", "APT41",
            "Lazarus", "Lazarus Group", "HIDDEN COBRA", "Fancy Bear", "Cozy Bear", "Sofacy",
            "APT28", "APT29", "The Dukes", "Carbanak", "Anunak", "BlackEnergy", "Cobalt",
            "Dragonfly", "Energetic Bear", "Equation Group", "Gamaredon", "Gorgon Group",
            "Kimsuky", "MuddyWater", "OilRig", "Panda", "Putter Panda", "Sandworm", "Silence",
            "Stuxnet", "Turla", "WannaCry", "Wizard Spider", "Zeus", "FIN7", "FIN8",
            "UNC2452", "UNC1878", "UNC1151", "UNC2447", "UNC3004", "UNC3524", "UNC3944"
        ]
        
        text_lower = text.lower()
        for actor in known_actors:
            if actor.lower() in text_lower:
                actors.append(actor)
        
        # APT pattern matching
        apt_pattern = re.compile(r'\bAPT\s*-?\s*\d+\b', re.IGNORECASE)
        apt_matches = apt_pattern.findall(text)
        actors.extend([m.strip() for m in apt_matches])
        
        # UNC pattern matching (Mandiant's naming)
        unc_pattern = re.compile(r'\bUNC\d+\b', re.IGNORECASE)
        unc_matches = unc_pattern.findall(text)
        actors.extend([m.strip() for m in unc_matches])
        
        # Remove duplicates
        seen = set()
        unique_actors = []
        for actor in actors:
            if actor not in seen:
                seen.add(actor)
                unique_actors.append(actor)
        
        return unique_actors[:10]  # Limit to 10 per report
    
    def _extract_industry_context(self, text: str, title: str) -> str:
        """Extract industry context from text and title"""
        # Industry keywords
        industry_keywords = {
            "financial": ["bank", "financial", "finance", "credit", "mortgage", "investment", "trading"],
            "healthcare": ["hospital", "healthcare", "medical", "pharmaceutical", "pharma", "clinic"],
            "energy": ["energy", "power", "utility", "electric", "oil", "gas", "petroleum"],
            "technology": ["technology", "software", "tech", "IT", "cloud", "saas", "platform"],
            "government": ["government", "federal", "state", "municipal", "defense", "military"],
            "manufacturing": ["manufacturing", "factory", "production", "industrial"],
            "retail": ["retail", "store", "commerce", "e-commerce", "shopping"],
            "education": ["education", "university", "school", "college", "academic"],
            "transportation": ["transportation", "logistics", "shipping", "aviation", "airline"]
        }
        
        combined_text = f"{title} {text}".lower()
        found_industries = []
        
        for industry, keywords in industry_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                found_industries.append(industry)
        
        return " ".join(found_industries) if found_industries else text[:200]
