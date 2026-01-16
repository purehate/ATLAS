"""
Google Threat Analysis Group (TAG) Blog Ingester
Scrapes threat intelligence from Google's TAG blog
"""
import httpx
from bs4 import BeautifulSoup
from datetime import date, datetime
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Source
from app.services.ingestion.normalizer import Normalizer
from app.services.ingestion.enhanced_extraction import (
    extract_actors_enhanced, extract_industries_enhanced, extract_techniques_enhanced
)
from app.utils.logging import setup_logging

logger = setup_logging()

GOOGLE_TAG_BASE_URL = "https://blog.google"
GOOGLE_TAG_BLOG_URL = f"{GOOGLE_TAG_BASE_URL}/threat-analysis-group/"
GOOGLE_TAG_RSS_URL = f"{GOOGLE_TAG_BASE_URL}/threat-analysis-group/feed/"


class GoogleTagIngester:
    """Ingest threat intelligence from Google Threat Analysis Group blog"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = Normalizer(db)
    
    async def _get_or_create_source(self) -> Source:
        """Get or create Google TAG source"""
        from sqlalchemy import select
        result = await self.db.execute(
            select(Source).where(Source.name == "Google Threat Analysis Group")
        )
        source = result.scalar_one_or_none()
        
        if not source:
            source = Source(
                name="Google Threat Analysis Group",
                type="blog",
                base_url=GOOGLE_TAG_BASE_URL,
                reliability_score=8,  # High reliability (Google)
                last_checked_at=date.today()
            )
            self.db.add(source)
            await self.db.commit()
            await self.db.refresh(source)
        
        return source
    
    async def ingest(self, limit: int = 50) -> Dict:
        """
        Ingest Google TAG blog posts
        Returns stats: {posts_processed, evidence_created}
        """
        logger.info("Starting Google Threat Analysis Group ingestion")
        
        # Get or create source
        source = await self._get_or_create_source()
        
        stats = {
            "posts_processed": 0,
            "evidence_created": 0
        }
        
        # Try HTML scraping (RSS feed returns 404)
        post_links = []
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                response = await client.get(GOOGLE_TAG_BLOG_URL)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "lxml")
                
                # Try multiple selectors
                selectors = [
                    "article a",
                    "h2 a, h3 a",
                    ".post a",
                    "a[href*='/threat-analysis-group/']",
                ]
                
                seen_urls = set()
                for selector in selectors:
                    links = soup.select(selector)
                    for link in links:
                        href = link.get("href", "")
                        if not href:
                            continue
                        
                        # Filter to actual blog posts
                        if "/threat-analysis-group/" in href and href.count("/") >= 4:
                            # Skip social media, tags, categories, feed
                            if any(skip in href for skip in ['twitter.com', 'facebook.com', 'linkedin.com', '/tag/', '/category/', '/author/', '/feed', '/rss']):
                                continue
                            
                            # Make absolute URL
                            if href.startswith("/"):
                                url = f"{GOOGLE_TAG_BASE_URL}{href}"
                            elif href.startswith("http"):
                                url = href
                            else:
                                continue
                            
                            # Must be a post URL (not the main page)
                            if url != GOOGLE_TAG_BLOG_URL and url not in seen_urls:
                                seen_urls.add(url)
                                post_links.append(url)
                    
                    if post_links:
                        break  # Found links with this selector
                
                logger.info(f"Found {len(post_links)} blog post links from HTML")
            except Exception as e:
                logger.error(f"Failed to fetch Google TAG blog: {e}")
                return {"error": str(e)}
        
        if not post_links:
            logger.warning("No blog post links found")
            return stats
        
        # Process posts (keep client open)
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            for url in post_links[:limit]:
                try:
                    evidence_count = await self._process_post(url, source, client)
                    if evidence_count > 0:
                        stats["posts_processed"] += 1
                        stats["evidence_created"] += evidence_count
                except Exception as e:
                    logger.error(f"Error processing post {url}: {e}")
                    continue
        
        # Update source
        source.last_checked_at = date.today()
        await self.db.commit()
        
        logger.info(f"Google TAG ingestion complete: {stats}")
        return stats
    
    async def _process_post(
        self, 
        url: str, 
        source: Source, 
        client: httpx.AsyncClient
    ) -> int:
        """Process a single blog post"""
        try:
            response = await client.get(url)
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return 0
        
        soup = BeautifulSoup(response.text, "lxml")
        
        # Extract title
        title_elem = soup.find("title") or soup.find("h1")
        title = title_elem.get_text(strip=True) if title_elem else "Untitled"
        
        # Extract date
        pub_date = None
        date_elem = soup.find("time") or soup.find(attrs={"datetime": True})
        if date_elem:
            if date_elem.get("datetime"):
                try:
                    pub_date = datetime.fromisoformat(date_elem.get("datetime").replace("Z", "+00:00")).date()
                except:
                    pass
            elif date_elem.get_text():
                # Try to parse text date
                try:
                    pub_date = datetime.strptime(date_elem.get_text(strip=True)[:10], "%Y-%m-%d").date()
                except:
                    pass
        
        if not pub_date:
            pub_date = date.today()
        
        # Extract main content
        content_elem = soup.find("article") or soup.find("main") or soup.find("div", class_=lambda x: x and "content" in x.lower())
        text = ""
        if content_elem:
            # Remove script and style tags
            for script in content_elem(["script", "style"]):
                script.decompose()
            text = content_elem.get_text(separator=" ", strip=True)
        else:
            text = soup.get_text(separator=" ", strip=True)
        
        if not text or len(text) < 100:
            logger.warning(f"Post {url} has insufficient content")
            return 0
        
        # Extract actors (use enhanced extraction)
        actors = extract_actors_enhanced(text, title)
        
        # Extract industries (use enhanced extraction)
        industries = extract_industries_enhanced(text, title)
        industry_text = " ".join(industries) if industries else ""
        
        # Extract techniques (use enhanced extraction)
        technique_ids = extract_techniques_enhanced(text)
        
        if not actors and not technique_ids:
            logger.debug(f"No actors or techniques found in {url}")
            return 0
        
        # Create evidence items
        evidence_count = 0
        if not actors:
            actors = ["Unknown"]  # Create at least one evidence item
        
        for actor_name in actors:
            items = await self.normalizer.create_evidence_item(
                actor_name=actor_name,
                source=source,
                source_url=url,
                source_title=title,
                source_date=pub_date,
                industry_keywords=industry_text if industry_text else None,
                technique_ids=technique_ids if technique_ids else None,
                excerpt=text[:500] if len(text) > 500 else text
            )
            evidence_count += len(items)
        
        return evidence_count
