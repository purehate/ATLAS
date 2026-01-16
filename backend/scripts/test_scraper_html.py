"""
Test script to analyze HTML structure of target sites
Helps identify correct selectors for scrapers
"""
import asyncio
import httpx
from bs4 import BeautifulSoup


async def test_mandiant():
    """Test Mandiant reports page structure"""
    print("=" * 70)
    print("Testing Mandiant Reports Page")
    print("=" * 70)
    
    url = "https://www.mandiant.com/resources/reports"
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
            print(f"Status: {response.status_code}")
            print(f"Final URL: {response.url}")
            print()
            
            soup = BeautifulSoup(response.text, "lxml")
            
            # Try different selectors
            selectors_to_try = [
                "article a",
                ".report-card a",
                ".resource-item a",
                "a[href*='/resources/reports/']",
                "a[href*='mandiant.com/resources/reports']",
                ".card a",
                ".post a",
                "h2 a",
                "h3 a",
            ]
            
            for selector in selectors_to_try:
                links = soup.select(selector)
                report_links = [l for l in links if "/resources/reports/" in l.get("href", "")]
                if report_links:
                    print(f"✓ Selector '{selector}' found {len(report_links)} report links")
                    print(f"  Sample: {report_links[0].get('href', '')[:80]}")
                    print(f"  Text: {report_links[0].get_text(strip=True)[:60]}")
                    print()
            
            # Check page structure
            print("Page structure:")
            print(f"  Title: {soup.title.string if soup.title else 'None'}")
            articles = soup.select("article")
            print(f"  <article> tags: {len(articles)}")
            
            # Look for common patterns
            cards = soup.select(".card, .report-card, .resource-card")
            print(f"  Cards: {len(cards)}")
            
        except Exception as e:
            print(f"Error: {e}")


async def test_microsoft():
    """Test Microsoft Security Blog page structure"""
    print("=" * 70)
    print("Testing Microsoft Security Blog")
    print("=" * 70)
    
    url = "https://www.microsoft.com/en-us/security/blog/"
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
            print(f"Status: {response.status_code}")
            print(f"Final URL: {response.url}")
            print()
            
            soup = BeautifulSoup(response.text, "lxml")
            
            # Try different selectors
            selectors_to_try = [
                "article a",
                "a[href*='/security/blog/']",
                ".blog-post a",
                ".post-item a",
                ".entry a",
                "h2 a",
                "h3 a",
                ".title a",
            ]
            
            for selector in selectors_to_try:
                links = soup.select(selector)
                blog_links = [l for l in links if "/security/blog/" in l.get("href", "") and l.get("href", "").count("/") >= 6]
                if blog_links:
                    print(f"✓ Selector '{selector}' found {len(blog_links)} blog links")
                    print(f"  Sample: {blog_links[0].get('href', '')[:80]}")
                    print(f"  Text: {blog_links[0].get_text(strip=True)[:60]}")
                    print()
            
            # Check page structure
            print("Page structure:")
            print(f"  Title: {soup.title.string if soup.title else 'None'}")
            articles = soup.select("article")
            print(f"  <article> tags: {len(articles)}")
            
        except Exception as e:
            print(f"Error: {e}")


async def test_cisa():
    """Test CISA advisories page structure"""
    print("=" * 70)
    print("Testing CISA Advisories")
    print("=" * 70)
    
    url = "https://www.cisa.gov/news-events/cybersecurity-advisories"
    
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
            print(f"Status: {response.status_code}")
            print()
            
            soup = BeautifulSoup(response.text, "lxml")
            
            # Try different selectors
            selectors_to_try = [
                "article.c-teaser a",
                "article[class*='teaser'] a",
                "a[href*='/news-events/cybersecurity-advisories/']",
                ".c-teaser a",
                "h2 a",
                "h3 a",
            ]
            
            for selector in selectors_to_try:
                links = soup.select(selector)
                # Filter to actual advisory pages (not filters, categories)
                advisory_links = []
                for link in links:
                    href = link.get("href", "")
                    if "/news-events/cybersecurity-advisories/" in href and "?" not in href:
                        advisory_links.append(link)
                
                if advisory_links:
                    print(f"✓ Selector '{selector}' found {len(advisory_links)} advisory links")
                    print(f"  Sample: {advisory_links[0].get('href', '')[:80]}")
                    print(f"  Text: {advisory_links[0].get_text(strip=True)[:60]}")
                    print()
            
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(test_mandiant())
    print()
    asyncio.run(test_microsoft())
    print()
    asyncio.run(test_cisa())
