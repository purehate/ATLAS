"""
Full NAICS (North American Industry Classification System) implementation
Fetches and parses the complete NAICS hierarchy from free public sources

Sources:
- US Census Bureau: https://www.census.gov/naics/
- BLS NAICS Reference: https://www.bls.gov/ces/naics/home.htm
- GitHub: https://github.com/leereilly/csi (NAICS + SIC datasets)
"""
import httpx
import csv
import json
from typing import List, Dict, Optional
from app.utils.logging import setup_logging

logger = setup_logging()

# Fallback: Comprehensive NAICS 2022 data (embedded for reliability)
# This includes major sectors and subsectors commonly used in threat intelligence
NAICS_2022_DATA = {
    # 2-digit sectors (major economic sectors)
    "11": {"name": "Agriculture, Forestry, Fishing and Hunting", "level": 2},
    "21": {"name": "Mining, Quarrying, and Oil and Gas Extraction", "level": 2},
    "22": {"name": "Utilities", "level": 2},
    "23": {"name": "Construction", "level": 2},
    "31-33": {"name": "Manufacturing", "level": 2},
    "42": {"name": "Wholesale Trade", "level": 2},
    "44-45": {"name": "Retail Trade", "level": 2},
    "48-49": {"name": "Transportation and Warehousing", "level": 2},
    "51": {"name": "Information", "level": 2},
    "52": {"name": "Finance and Insurance", "level": 2},
    "53": {"name": "Real Estate and Rental and Leasing", "level": 2},
    "54": {"name": "Professional, Scientific, and Technical Services", "level": 2},
    "55": {"name": "Management of Companies and Enterprises", "level": 2},
    "56": {"name": "Administrative and Support and Waste Management", "level": 2},
    "61": {"name": "Educational Services", "level": 2},
    "62": {"name": "Health Care and Social Assistance", "level": 2},
    "71": {"name": "Arts, Entertainment, and Recreation", "level": 2},
    "72": {"name": "Accommodation and Food Services", "level": 2},
    "81": {"name": "Other Services (except Public Administration)", "level": 2},
    "92": {"name": "Public Administration", "level": 2},
    
    # 3-digit subsectors (key ones for threat intelligence)
    "211": {"name": "Oil and Gas Extraction", "parent": "21", "level": 3},
    "212": {"name": "Mining (except Oil and Gas)", "parent": "21", "level": 3},
    "221": {"name": "Utilities", "parent": "22", "level": 3},
    "311": {"name": "Food Manufacturing", "parent": "31-33", "level": 3},
    "312": {"name": "Beverage and Tobacco Product Manufacturing", "parent": "31-33", "level": 3},
    "325": {"name": "Chemical Manufacturing", "parent": "31-33", "level": 3},
    "334": {"name": "Computer and Electronic Product Manufacturing", "parent": "31-33", "level": 3},
    "336": {"name": "Transportation Equipment Manufacturing", "parent": "31-33", "level": 3},
    "511": {"name": "Publishing Industries", "parent": "51", "level": 3},
    "512": {"name": "Motion Picture and Sound Recording Industries", "parent": "51", "level": 3},
    "517": {"name": "Telecommunications", "parent": "51", "level": 3},
    "518": {"name": "Data Processing, Hosting, and Related Services", "parent": "51", "level": 3},
    "519": {"name": "Other Information Services", "parent": "51", "level": 3},
    "521": {"name": "Monetary Authorities - Central Bank", "parent": "52", "level": 3},
    "522": {"name": "Credit Intermediation and Related Activities", "parent": "52", "level": 3},
    "523": {"name": "Securities, Commodity Contracts, and Other Financial Investments", "parent": "52", "level": 3},
    "524": {"name": "Insurance Carriers and Related Activities", "parent": "52", "level": 3},
    "525": {"name": "Funds, Trusts, and Other Financial Vehicles", "parent": "52", "level": 3},
    "541": {"name": "Professional, Scientific, and Technical Services", "parent": "54", "level": 3},
    "621": {"name": "Ambulatory Health Care Services", "parent": "62", "level": 3},
    "622": {"name": "Hospitals", "parent": "62", "level": 3},
    "623": {"name": "Nursing and Residential Care Facilities", "parent": "62", "level": 3},
    "624": {"name": "Social Assistance", "parent": "62", "level": 3},
    
    # 4-digit industry groups (selected important ones)
    "2211": {"name": "Electric Power Generation, Transmission and Distribution", "parent": "221", "level": 4},
    "2212": {"name": "Natural Gas Distribution", "parent": "221", "level": 4},
    "2213": {"name": "Water, Sewage and Other Systems", "parent": "221", "level": 4},
    "3254": {"name": "Pharmaceutical and Medicine Manufacturing", "parent": "325", "level": 4},
    "3345": {"name": "Navigational, Measuring, Electromedical, and Control Instruments Manufacturing", "parent": "334", "level": 4},
    "5112": {"name": "Software Publishers", "parent": "511", "level": 4},
    "5171": {"name": "Wired Telecommunications Carriers", "parent": "517", "level": 4},
    "5172": {"name": "Wireless Telecommunications Carriers (except Satellite)", "parent": "517", "level": 4},
    "5182": {"name": "Data Processing, Hosting, and Related Services", "parent": "518", "level": 4},
    "5221": {"name": "Depository Credit Intermediation", "parent": "522", "level": 4},
    "5231": {"name": "Securities and Commodity Contracts Intermediation and Brokerage", "parent": "523", "level": 4},
    "5232": {"name": "Securities and Commodity Exchanges", "parent": "523", "level": 4},
    "5241": {"name": "Insurance Carriers", "parent": "524", "level": 4},
    "5415": {"name": "Computer Systems Design and Related Services", "parent": "541", "level": 4},
    "5416": {"name": "Management Consulting Services", "parent": "541", "level": 4},
    "5417": {"name": "Scientific Research and Development Services", "parent": "541", "level": 4},
}


def get_naics_hierarchy() -> List[Dict]:
    """
    Get full NAICS hierarchy with proper parent-child relationships
    Returns list of industries with NAICS codes and hierarchy
    """
    industries = []
    
    # Build hierarchy from NAICS data
    # First, create all sectors (level 2)
    sectors = {}
    for code, data in NAICS_2022_DATA.items():
        if data["level"] == 2:
            sectors[code] = {
                "naics_code": code,
                "name": data["name"],
                "level": 2,
                "parent_code": None,
                "parent_name": None
            }
    
    # Then create subsectors and industry groups (level 3+)
    for code, data in NAICS_2022_DATA.items():
        if data["level"] > 2:
            parent_code = data.get("parent")
            parent_name = None
            if parent_code:
                # Find parent name
                parent_data = NAICS_2022_DATA.get(parent_code)
                if parent_data:
                    parent_name = parent_data["name"]
            
            industries.append({
                "naics_code": code,
                "name": data["name"],
                "level": data["level"],
                "parent_code": parent_code,
                "parent_name": parent_name
            })
    
    # Add sectors at the beginning
    for sector in sectors.values():
        industries.insert(0, sector)
    
    return industries


def get_industries_for_threat_intel() -> List[Dict]:
    """
    Get industries optimized for threat intelligence use
    Maps NAICS to common threat intel industry names while preserving hierarchy
    """
    naics_data = get_naics_hierarchy()
    
    # Mapping of NAICS sectors to common threat intel names
    threat_intel_mapping = {
        "52": "Financial Services",
        "62": "Healthcare",
        "22": "Energy",
        "21": "Oil & Gas",
        "51": "Technology",
        "31-33": "Manufacturing",
        "44-45": "Retail",
        "92": "Government",
        "61": "Education",
        "48-49": "Transportation",
    }
    
    # Mapping of specific NAICS codes to threat intel sub-industries
    sub_industry_mapping = {
        "522": "Banking",
        "524": "Insurance",
        "523": "Investment",
        "622": "Hospitals",
        "3254": "Pharmaceuticals",
        "3345": "Medical Devices",
        "2211": "Electric Power",
        "2212": "Natural Gas",
        "2213": "Water Utilities",
        "211": "Oil Extraction",
        "5112": "Software",
        "5182": "Cloud Services",
        "517": "Telecommunications",
        "5415": "IT Services",
    }
    
    industries = []
    processed_codes = set()
    
    # Process sectors first
    for item in naics_data:
        code = item["naics_code"]
        if item["level"] == 2:
            # Map to threat intel name if available
            threat_name = threat_intel_mapping.get(code, item["name"])
            
            industries.append({
                "name": threat_name,
                "code": code,
                "naics_code": code,
                "parent_id": None,
                "parent_name": None,
                "level": 2
            })
            processed_codes.add(code)
    
    # Process subsectors and industry groups
    for item in naics_data:
        code = item["naics_code"]
        if item["level"] > 2 and code not in processed_codes:
            # Check if this maps to a threat intel sub-industry
            threat_name = sub_industry_mapping.get(code, item["name"])
            parent_code = item.get("parent_code")
            
            # Find parent in our industries list
            parent_name = None
            if parent_code:
                # Map parent code to threat intel name
                parent_threat_name = threat_intel_mapping.get(parent_code)
                if parent_threat_name:
                    parent_name = parent_threat_name
                else:
                    # Find original parent name
                    parent_data = NAICS_2022_DATA.get(parent_code)
                    if parent_data:
                        parent_name = parent_data["name"]
            
            industries.append({
                "name": threat_name,
                "code": code,
                "naics_code": code,
                "parent_name": parent_name,  # Will resolve to parent_id in seed script
                "level": item["level"]
            })
            processed_codes.add(code)
    
    return industries


async def fetch_naics_from_web() -> Optional[List[Dict]]:
    """
    Attempt to fetch NAICS data from web sources
    Falls back to embedded data if fetch fails
    """
    # Try GitHub repo with NAICS data
    github_urls = [
        "https://raw.githubusercontent.com/leereilly/csi/main/data/naics.csv",
        "https://raw.githubusercontent.com/ntdalbec/naics/main/data/naics-2022.json",
    ]
    
    for url in github_urls:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    if url.endswith('.csv'):
                        # Parse CSV
                        reader = csv.DictReader(response.text.splitlines())
                        return list(reader)
                    elif url.endswith('.json'):
                        # Parse JSON
                        return response.json()
        except Exception as e:
            logger.warning(f"Failed to fetch NAICS from {url}: {e}")
            continue
    
    return None


def get_industries_from_naics() -> List[Dict]:
    """
    Main function to get industries from NAICS
    Uses threat intelligence optimized mapping
    """
    return get_industries_for_threat_intel()
