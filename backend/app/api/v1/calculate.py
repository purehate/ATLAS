from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.schemas import CalculateRequest, CalculateResponse
from app.services.calculator import CalculatorService
from app.services.breach_detection import BreachDetectionService

router = APIRouter()


@router.post("/calculate", response_model=CalculateResponse)
async def calculate(
    request: CalculateRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Calculate top 5 threat actor groups for given industry
    Includes breach detection if company name is provided
    """
    calculator = CalculatorService(db)
    
    try:
        result = await calculator.calculate(
            business_vertical=request.business_vertical,
            sub_vertical=request.sub_vertical
        )
        
        # Add breach detection if company name provided
        if request.company_name:
            breach_service = BreachDetectionService(db)
            breach_info = await breach_service.check_company_breach(
                company_name=request.company_name,
                industry_keywords=request.business_vertical
            )
            # Add breach info to metadata
            if result.metadata:
                result.metadata["breach_detection"] = breach_info
            else:
                result.metadata = {"breach_detection": breach_info}
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
