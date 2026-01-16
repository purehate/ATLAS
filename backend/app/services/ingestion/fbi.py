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
from app.utils.logging import setup_logging

logger = setup_logging()

FBI_BASE_URL = "https://www.ic3.gov"
FBI_NEWS_URL = f"{FBI_BASE_URL}/Media/News"
FBI_CSA_URL = f"{FBI_BASE_URL}/CSA"


class FbiIngester:
    """Ingest data from FBI IC3 Flash Reports"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
    
    async def ingest(self, limit: int = 30) -> Dict[str, int]:
        """
        Ingest FBI Flash Reports and CSA PDFs
        Returns stats: {reports_processed, evidence_created}
        """
        logger.info("Starting FBI Flash Reports ingestion")
        
        # Get or create FBI source
        source = await self._get_or_create_source()
        
        stats = {
            "reports_processed": 0,
            "evidence_created": 0
        }
        
        # Try CSA page first (has PDFs)
        pdf_urls = []
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.get(FBI_CSA_URL)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "lxml")
                    # Find PDF links
                    for link in soup.find_all("a", href=True):
                        href = link.get("href", "")
                        if ".pdf" in href.lower():
                            if href.startswith("/"):
                                url = f"{FBI_BASE_URL}{href}"
                            elif href.startswith("http"):
                                url = href
                            else:
                                continue
                            if url not in pdf_urls:
                                pdf_urls.append(url)
                    
                    logger.info(f"Found {len(pdf_urls)} PDF links from CSA page")
            except Exception as e:
                logger.warning(f"Failed to fetch CSA page: {e}")
            
            # Also try to find PDFs by date pattern (last 30 days)
            from datetime import timedelta
            today = date.today()
            for i in range(30):
                check_date = today - timedelta(days=i)
                pdf_path = f"/CSA/{check_date.year}/{check_date.strftime('%y%m%d')}.pdf"
                pdf_url = f"{FBI_BASE_URL}{pdf_path}"
                if pdf_url not in pdf_urls:
                    pdf_urls.append(pdf_url)
            
            # Process PDFs
            for pdf_url in pdf_urls[:limit]:
                try:
                    evidence_count = await self._process_pdf(pdf_url, source, client)
                    if evidence_count > 0:
                        stats["reports_processed"] += 1
                        stats["evidence_created"] += evidence_count
                except Exception as e:
                    logger.debug(f"Error processing PDF {pdf_url}: {e}")
                    continue
        
        # Update source last_checked_at
        source.last_checked_at = date.today()
        await self.db.commit()
        
        logger.info(f"FBI ingestion complete: {stats}")
        return stats
    
    async def _get_or_create_source(self) -> Source:
        """Get or create FBI source"""
        result = await self.db.execute(
            select(Source).where(Source.name == "FBI Flash Report")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            from config import settings
            source = Source(
                name="FBI Flash Report",
                type="report",
                base_url=FBI_BASE_URL,
                reliability_score=settings.source_reliability_fbi,
                meta_data={"news_url": FBI_NEWS_URL}
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
        """Process a single FBI report"""
        try:
            response = await client.get(url, timeout=15.0)
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return 0
        
        soup = BeautifulSoup(response.text, "lxml")
        
        # Extract title
        title_elem = soup.select_one("h1, .page-title, title")
        title = title_elem.get_text(strip=True) if title_elem else "FBI Flash Report"
        
        # Extract date
        date_elem = soup.select_one("time, .date, .published-date")
        source_date = date.today()
        if date_elem:
            date_text = date_elem.get_text(strip=True)
            try:
                from dateutil import parser
                source_date = parser.parse(date_text).date()
            except:
                pass
        
        # Extract text content
        content_elem = soup.select_one("article, .content, .body, main")
        if not content_elem:
            content_elem = soup
        
        text = content_elem.get_text(separator=" ", strip=True)
        
        # Extract actor names
        actors = self._extract_actors(text)
        
        # Extract industry keywords
        industry_text = text
        
        # Extract technique IDs
        technique_ids = extract_technique_ids(text)
        
        # Create evidence items
        evidence_count = 0
        for actor_name in actors:
            items = await self.normalizer.create_evidence_item(
                actor_name=actor_name,
                industry_keywords=industry_text,
                technique_ids=technique_ids if technique_ids else None,
                source=source,
                source_url=url,
                source_title=title,
                source_date=source_date,
                excerpt=text[:500] if len(text) > 500 else text
            )
            evidence_count += len(items)
        
        return evidence_count
    
    def _extract_actors(self, text: str) -> List[str]:
        """Extract threat actor names from text"""
        # Similar to CISA ingester
        actors = []
        
        known_actors = [
            "Lazarus Group", "APT28", "APT29", "Fancy Bear", "Cozy Bear",
            "APT1", "APT10", "APT12", "APT17", "APT18", "APT19", "APT20",
            "APT21", "APT22", "APT23", "APT27", "APT30", "APT31", "APT32",
            "APT33", "APT34", "APT35", "APT36", "APT37", "APT38", "APT39",
            "APT40", "APT41", "BlackEnergy", "Carbanak", "Cobalt", "Dragonfly",
            "Energetic Bear", "Equation Group", "Gamaredon", "Gorgon Group",
            "HIDDEN COBRA", "Kimsuky", "Lazarus", "MuddyWater", "OilRig",
            "Panda", "Putter Panda", "Sandworm", "Silence", "Sofacy",
            "Stuxnet", "Turla", "WannaCry", "Wizard Spider", "Zeus"
        ]
        
        text_lower = text.lower()
        for actor in known_actors:
            if actor.lower() in text_lower:
                actors.append(actor)
        
        apt_pattern = re.compile(r'APT\s*-?\s*\d+', re.IGNORECASE)
        apt_matches = apt_pattern.findall(text)
        actors.extend([m.strip() for m in apt_matches])
        
        seen = set()
        unique_actors = []
        for actor in actors:
            if actor not in seen:
                seen.add(actor)
                unique_actors.append(actor)
        
        return unique_actors[:10]
    
    async def _process_pdf(
        self,
        url: str,
        source: Source,
        client: httpx.AsyncClient
    ) -> int:
        """Process a PDF file from IC3 CSA"""
        try:
            response = await client.get(url, timeout=15.0)
            if response.status_code != 200:
                return 0
        except Exception as e:
            logger.debug(f"Failed to fetch PDF {url}: {e}")
            return 0
        
        # Extract text from PDF using pdfplumber (better) or PyPDF2 (fallback)
        text = ""
        try:
            import pdfplumber
            import io
            
            with pdfplumber.open(io.BytesIO(response.content)) as pdf:
                # Extract text from all pages
                pages_text = []
                for page in pdf.pages[:5]:  # Limit to first 5 pages
                    page_text = page.extract_text()
                    if page_text:
                        pages_text.append(page_text)
                text = " ".join(pages_text)
        except ImportError:
            # Fallback to PyPDF2
            try:
                import PyPDF2
                import io
                
                pdf_file = io.BytesIO(response.content)
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                pages_text = []
                for page_num in range(min(5, len(pdf_reader.pages))):  # Limit to first 5 pages
                    page = pdf_reader.pages[page_num]
                    page_text = page.extract_text()
                    if page_text:
                        pages_text.append(page_text)
                text = " ".join(pages_text)
            except ImportError:
                logger.warning("No PDF parsing library available. Install pdfplumber or PyPDF2.")
                return 0
        except Exception as e:
            logger.debug(f"Error extracting text from PDF {url}: {e}")
            return 0
        
        if len(text) < 100:
            logger.debug(f"PDF {url} has insufficient text ({len(text)} chars)")
            return 0
        
        # Extract date from URL (format: /CSA/YYYY/YYMMDD.pdf)
        source_date = date.today()
        try:
            url_parts = url.split('/')
            if len(url_parts) >= 3:
                year = url_parts[-2]
                date_str = url_parts[-1].replace('.pdf', '')
                if len(date_str) == 6:
                    source_date = datetime.strptime(f"{year}{date_str}", "%Y%y%m%d").date()
        except:
            pass
        
        # Extract actors (use enhanced extraction)
        from app.services.ingestion.enhanced_extraction import (
            extract_actors_enhanced, extract_industries_enhanced, extract_techniques_enhanced
        )
        actors = extract_actors_enhanced(text, title)
        if not actors:
            actors = self._extract_actors(text)
        
        # Extract industries (use enhanced extraction)
        industries = extract_industries_enhanced(text, title)
        industry_text = ", ".join(industries) if industries else text[:200]
        
        # Extract techniques (use enhanced extraction)
        technique_ids = extract_techniques_enhanced(text)
        if not technique_ids:
            technique_ids = extract_technique_ids(text)
        
        if not actors and not technique_ids:
            logger.debug(f"No actors or techniques found in PDF {url}")
            return 0
        
        # Create evidence items
        evidence_count = 0
        title = f"IC3 CSA Alert {source_date.strftime('%Y-%m-%d')}"
        if not actors:
            actors = ["Unknown"]  # Create at least one evidence item
        
        for actor_name in actors:
            items = await self.normalizer.create_evidence_item(
                actor_name=actor_name,
                industry_keywords=industry_text,
                technique_ids=technique_ids if technique_ids else None,
                source=source,
                source_url=url,
                source_title=title,
                source_date=source_date,
                excerpt=text[:500] if len(text) > 500 else text
            )
            evidence_count += len(items)
        
        return evidence_count