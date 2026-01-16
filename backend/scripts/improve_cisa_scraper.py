"""
Script to test and improve CISA scraper
This helps identify the correct HTML selectors
"""
import asyncio
import httpx
from bs4 import BeautifulSoup

CISA_ADVISORIES_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories"


async def test_cisa_structure():
    """Test CISA page structure to find correct selectors"""
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            response = await client.get(CISA_ADVISORIES_URL)
            response.raise_for_status()
        except Exception as e:
            print(f"Error fetching: {e}")
            return
    
    soup = BeautifulSoup(response.text, "lxml")
    
    print("Testing CISA page structure...")
    print("=" * 60)
    
    # Try different selectors
    selectors_to_try = [
        "article a",
        ".c-view__row a",
        "article.c-view__row a",
        ".view-content a",
        ".field-content a",
        "h2 a",
        "h3 a",
        ".node a",
        "[class*='advisory'] a",
        "[class*='cyber'] a",
    ]
    
    for selector in selectors_to_try:
        links = soup.select(selector)
        advisory_links = [l for l in links if "cybersecurity-advisories" in l.get("href", "")]
        if advisory_links:
            print(f"\n✓ Selector '{selector}' found {len(advisory_links)} advisory links")
            print(f"  Sample: {advisory_links[0].get('href', '')[:80]}")
            print(f"  Text: {advisory_links[0].get_text(strip=True)[:60]}")
    
    # Also check for RSS feed
    rss_links = soup.select('link[type="application/rss+xml"], a[href*="rss"], a[href*="feed"]')
    if rss_links:
        print(f"\n✓ Found RSS feed: {rss_links[0].get('href', '')}")
    
    # Check page structure
    print("\nPage structure analysis:")
    print(f"  Title: {soup.title.string if soup.title else 'None'}")
    
    # Look for common patterns
    articles = soup.select("article")
    print(f"  <article> tags: {len(articles)}")
    
    divs_with_class = soup.select("div[class*='view'], div[class*='advisory']")
    print(f"  Relevant divs: {len(divs_with_class)}")
    
    # Print sample HTML structure
    if articles:
        print(f"\nSample article HTML structure:")
        print(str(articles[0])[:500])


if __name__ == "__main__":
    asyncio.run(test_cisa_structure())
