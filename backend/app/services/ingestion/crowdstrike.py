"""
CrowdStrike Blog Ingestion
CrowdStrike publishes threat intelligence reports with actor and industry information
URL: https://www.crowdstrike.com/blog/
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

CROWDSTRIKE_BASE_URL = "https://www.crowdstrike.com"
CROWDSTRIKE_BLOG_URL = f"{CROWDSTRIKE_BASE_URL}/en-us/blog/"
CROWDSTRIKE_RSS_URL = f"{CROWDSTRIKE_BASE_URL}/en-us/blog/feed/"


class CrowdStrikeIngester:
    """Ingest data from CrowdStrike Blog"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
    
    async def ingest(self, limit: int = 20) -> Dict[str, int]:
        """
        Ingest CrowdStrike blog posts
        Returns stats: {posts_processed, evidence_created}
        """
        logger.info("Starting CrowdStrike Blog ingestion")
        
        # Get or create CrowdStrike source
        source = await self._get_or_create_source()
        
        stats = {
            "posts_processed": 0,
            "evidence_created": 0
        }
        
        # Fetch RSS feed (more reliable than scraping HTML)
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                # Try RSS feed first
                response = await client.get(CROWDSTRIKE_RSS_URL)
                response.raise_for_status()
                
                # Parse RSS feed
                soup = BeautifulSoup(response.text, "xml")
                items = soup.find_all("item")
                
                post_links = []
                for item in items:
                    link_elem = item.find("link")
                    if link_elem:
                        url = link_elem.text.strip()
                        if url and "/en-us/blog/" in url:
                            post_links.append(url)
                
                logger.info(f"Found {len(post_links)} blog posts from RSS feed")
                
            except Exception as e:
                logger.warning(f"RSS feed failed, trying HTML: {e}")
                # Fallback to HTML scraping
                try:
                    response = await client.get(CROWDSTRIKE_BLOG_URL)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, "lxml")
                    
                    # Find blog post links in HTML (fallback)
                    post_links = []
                    seen_urls = set()
                    
                    # Try multiple selectors
                    selectors = [
                        "article a[href*='/blog/']",
                        ".blog-post a",
                        ".post-item a",
                        "a[href*='crowdstrike.com/blog']",
                        "h2 a, h3 a"
                    ]
                    
                    for selector in selectors:
                        links = soup.select(selector)
                        for link in links:
                            href = link.get("href", "")
                            if href and "/blog/" in href:
                                if href.startswith("/"):
                                    url = f"{CROWDSTRIKE_BASE_URL}{href}"
                                elif href.startswith("http"):
                                    url = href
                                else:
                                    continue
                                
                                if "/blog/" in url and url.count("/") >= 5 and url not in seen_urls:
                                    seen_urls.add(url)
                                    post_links.append(url)
                except Exception as e2:
                    logger.error(f"Failed to fetch CrowdStrike Blog: {e2}")
                    return {"error": str(e2)}
            
            # Process posts
            for url in post_links[:limit]:
                try:
                    evidence_count = await self._process_post(url, source, client)
                    if evidence_count > 0:
                        stats["posts_processed"] += 1
                        stats["evidence_created"] += evidence_count
                except Exception as e:
                    logger.error(f"Error processing post {url}: {e}")
                    continue
        
        # Update source last_checked_at
        source.last_checked_at = date.today()
        await self.db.commit()
        
        logger.info(f"CrowdStrike Blog ingestion complete: {stats}")
        return stats
    
    async def _get_or_create_source(self) -> Source:
        """Get or create CrowdStrike source"""
        result = await self.db.execute(
            select(Source).where(Source.name == "CrowdStrike Blog")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            from config import settings
            source = Source(
                name="CrowdStrike Blog",
                type="report",
                base_url=CROWDSTRIKE_BASE_URL,
                reliability_score=8,  # High reliability
                meta_data={"blog_url": CROWDSTRIKE_BLOG_URL}
            )
            self.db.add(source)
            await self.db.flush()
        
        return source
    
    async def _process_post(
        self,
        url: str,
        source: Source,
        client: httpx.AsyncClient
    ) -> int:
        """Process a single CrowdStrike blog post"""
        try:
            response = await client.get(url, timeout=15.0)
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return 0
        
        soup = BeautifulSoup(response.text, "lxml")
        
        # Extract title
        title_elem = soup.select_one("h1, .page-title, title, .post-title")
        title = title_elem.get_text(strip=True) if title_elem else "CrowdStrike Blog Post"
        
        # Extract date
        date_elem = soup.select_one("time, .date, .published-date, .post-date")
        source_date = date.today()
        if date_elem:
            date_text = date_elem.get_text(strip=True)
            try:
                from dateutil import parser
                source_date = parser.parse(date_text).date()
            except:
                pass
        
        # Extract text content
        content_elem = soup.select_one("article, .content, .body, main, .post-content")
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
            "APT1", "APT28", "APT29", "APT38", "Lazarus", "Fancy Bear", "Cozy Bear",
            "Sofacy", "The Dukes", "Carbanak", "BlackEnergy", "Cobalt", "Dragonfly",
            "Energetic Bear", "Equation Group", "Gamaredon", "Kimsuky", "MuddyWater",
            "OilRig", "Sandworm", "Stuxnet", "Turla", "WannaCry", "Wizard Spider",
            "FIN7", "FIN8", "UNC2452", "UNC1878", "UNC1151", "Nobelium",
            "Scattered Spider", "Vice Society", "ALPHV", "BlackCat", "LockBit"
        ]
        
        text_lower = text.lower()
        for actor in known_actors:
            if actor.lower() in text_lower:
                actors.append(actor)
        
        # APT pattern matching
        apt_pattern = re.compile(r'\bAPT\s*-?\s*\d+\b', re.IGNORECASE)
        apt_matches = apt_pattern.findall(text)
        actors.extend([m.strip() for m in apt_matches])
        
        # UNC pattern matching
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
        
        return unique_actors[:10]
    
    def _extract_industry_context(self, text: str, title: str) -> str:
        """Extract industry context from text and title"""
        # Industry keywords
        industry_keywords = {
            "financial": ["bank", "financial", "finance", "credit", "mortgage", "investment"],
            "healthcare": ["hospital", "healthcare", "medical", "pharmaceutical", "pharma"],
            "energy": ["energy", "power", "utility", "electric", "oil", "gas"],
            "technology": ["technology", "software", "tech", "IT", "cloud", "saas"],
            "government": ["government", "federal", "state", "defense", "military"],
            "manufacturing": ["manufacturing", "factory", "production", "industrial"],
            "retail": ["retail", "store", "commerce", "e-commerce"],
            "education": ["education", "university", "school", "college"],
            "transportation": ["transportation", "logistics", "shipping", "aviation"]
        }
        
        combined_text = f"{title} {text}".lower()
        found_industries = []
        
        for industry, keywords in industry_keywords.items():
            if any(keyword in combined_text for keyword in keywords):
                found_industries.append(industry)
        
        return " ".join(found_industries) if found_industries else text[:200]
