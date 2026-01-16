"""
NAICS (North American Industry Classification System) industry data fetcher
NAICS is a free, public classification system maintained by the US Census Bureau
"""
import httpx
from typing import List, Dict
from app.utils.logging import setup_logging

logger = setup_logging()

# NAICS 2-digit sector codes (simplified for MVP)
# Full NAICS data is available from: https://www.census.gov/naics/
NAICS_SECTORS = {
    "11": {"name": "Agriculture, Forestry, Fishing and Hunting", "subsectors": []},
    "21": {"name": "Mining, Quarrying, and Oil and Gas Extraction", "subsectors": [
        "211", "212", "213"
    ]},
    "22": {"name": "Utilities", "subsectors": [
        "221"
    ]},
    "23": {"name": "Construction", "subsectors": []},
    "31-33": {"name": "Manufacturing", "subsectors": [
        "311", "312", "313", "314", "315", "316", "321", "322", "323", "324", "325", "326", "327", "331", "332", "333", "334", "335", "336", "337", "339"
    ]},
    "42": {"name": "Wholesale Trade", "subsectors": []},
    "44-45": {"name": "Retail Trade", "subsectors": []},
    "48-49": {"name": "Transportation and Warehousing", "subsectors": []},
    "51": {"name": "Information", "subsectors": [
        "511", "512", "515", "517", "518", "519"
    ]},
    "52": {"name": "Finance and Insurance", "subsectors": [
        "521", "522", "523", "524", "525"
    ]},
    "53": {"name": "Real Estate and Rental and Leasing", "subsectors": []},
    "54": {"name": "Professional, Scientific, and Technical Services", "subsectors": [
        "541"
    ]},
    "55": {"name": "Management of Companies and Enterprises", "subsectors": []},
    "56": {"name": "Administrative and Support and Waste Management", "subsectors": []},
    "61": {"name": "Educational Services", "subsectors": []},
    "62": {"name": "Health Care and Social Assistance", "subsectors": [
        "621", "622", "623", "624"
    ]},
    "71": {"name": "Arts, Entertainment, and Recreation", "subsectors": []},
    "72": {"name": "Accommodation and Food Services", "subsectors": []},
    "81": {"name": "Other Services (except Public Administration)", "subsectors": []},
    "92": {"name": "Public Administration", "subsectors": []},
}

# Mapping to common industry names for threat intelligence
INDUSTRY_MAPPING = {
    "Finance and Insurance": {
        "name": "Financial Services",
        "subsectors": [
            {"name": "Banking", "codes": ["522"]},
            {"name": "Insurance", "codes": ["524"]},
            {"name": "Investment", "codes": ["523"]},
            {"name": "Credit Intermediation", "codes": ["522"]},
        ]
    },
    "Health Care and Social Assistance": {
        "name": "Healthcare",
        "subsectors": [
            {"name": "Hospitals", "codes": ["622"]},
            {"name": "Pharmaceuticals", "codes": ["3254"]},
            {"name": "Medical Devices", "codes": ["3345"]},
            {"name": "Health Services", "codes": ["621"]},
        ]
    },
    "Utilities": {
        "name": "Energy",
        "subsectors": [
            {"name": "Electric Power", "codes": ["2211"]},
            {"name": "Natural Gas", "codes": ["2212"]},
            {"name": "Water Utilities", "codes": ["2213"]},
        ]
    },
    "Mining, Quarrying, and Oil and Gas Extraction": {
        "name": "Oil & Gas",
        "subsectors": [
            {"name": "Oil Extraction", "codes": ["211"]},
            {"name": "Gas Extraction", "codes": ["211"]},
        ]
    },
    "Information": {
        "name": "Technology",
        "subsectors": [
            {"name": "Software", "codes": ["5112", "5415"]},
            {"name": "Cloud Services", "codes": ["5182"]},
            {"name": "Telecommunications", "codes": ["517"]},
        ]
    },
    "Manufacturing": {
        "name": "Manufacturing",
        "subsectors": []
    },
    "Retail Trade": {
        "name": "Retail",
        "subsectors": []
    },
    "Public Administration": {
        "name": "Government",
        "subsectors": []
    },
    "Educational Services": {
        "name": "Education",
        "subsectors": []
    },
    "Transportation and Warehousing": {
        "name": "Transportation",
        "subsectors": []
    },
}


def get_industries_from_naics() -> List[Dict]:
    """
    Get industry list based on NAICS classification
    Returns list of industries with parent-child relationships
    """
    industries = []
    
    # Use our mapping which combines NAICS with common threat intel industry names
    for naics_name, mapping in INDUSTRY_MAPPING.items():
        # Add parent industry
        parent = {
            "name": mapping["name"],
            "code": mapping["name"].upper().replace(" ", "_").replace("&", "AND")[:10],
            "parent_id": None,
            "naics_codes": mapping.get("codes", [])
        }
        industries.append(parent)
        
        # Add subsectors
        for subsector in mapping.get("subsectors", []):
            industries.append({
                "name": subsector["name"],
                "code": subsector["name"].upper().replace(" ", "_")[:10],
                "parent_name": mapping["name"],  # Will resolve to parent_id later
                "naics_codes": subsector.get("codes", [])
            })
    
    return industries


async def fetch_naics_data() -> List[Dict]:
    """
    Fetch NAICS data from a free source (if available)
    For now, returns our curated list based on NAICS structure
    """
    # In the future, could fetch from:
    # - US Census Bureau API
    # - Open data portals
    # For MVP, using curated list based on NAICS structure
    return get_industries_from_naics()
