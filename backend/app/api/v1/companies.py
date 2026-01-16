"""
Company lookup and validation API endpoints
"""
from fastapi import APIRouter, Query, HTTPException, Depends
from app.services.company_lookup import CompanyLookupService
from app.db import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

router = APIRouter()


@router.get("/companies/search")
async def search_companies(
    q: str = Query(..., description="Company name to search for", min_length=2),
    limit: int = Query(10, ge=1, le=20, description="Maximum number of results"),
    jurisdiction: Optional[str] = Query(None, description="Jurisdiction code (e.g., 'us', 'gb', 'ca')"),
    db: AsyncSession = Depends(get_db)
):
    """
    Search for companies by name
    Returns a list of matching companies with details
    """
    lookup_service = CompanyLookupService()
    
    try:
        results = await lookup_service.search_companies(q, limit=limit, jurisdiction=jurisdiction)
        return {
            "query": q,
            "count": len(results),
            "companies": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Company search failed: {str(e)}")


@router.get("/companies/validate")
async def validate_company(
    name: str = Query(..., description="Company name to validate", min_length=2),
    jurisdiction: Optional[str] = Query(None, description="Jurisdiction code"),
    db: AsyncSession = Depends(get_db)
):
    """
    Validate a company name and get confidence score
    """
    lookup_service = CompanyLookupService()
    
    try:
        validation = await lookup_service.validate_company_name(name)
        return validation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Company validation failed: {str(e)}")


@router.get("/companies/details")
async def get_company_details(
    name: str = Query(..., description="Company name"),
    jurisdiction: Optional[str] = Query(None, description="Jurisdiction code"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a company
    """
    lookup_service = CompanyLookupService()
    
    try:
        details = await lookup_service.get_company_details(name, jurisdiction=jurisdiction)
        if not details:
            raise HTTPException(status_code=404, detail="Company not found")
        return details
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get company details: {str(e)}")
