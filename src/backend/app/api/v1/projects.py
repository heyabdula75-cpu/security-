"""
Project Management API routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.services.auth_service import get_user_by_id
from app.services.project_service import (
    create_project as create_project_service,
    delete_project as delete_project_service,
    get_project as get_project_service,
    list_projects as list_projects_service,
    update_project as update_project_service,
)

router = APIRouter()


@router.post("/projects", status_code=201)
async def create_project(
    name: str,
    description: str = "",
    repository_url: str | None = None,
    repository_type: str | None = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new project"""
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    project = await create_project_service(
        db,
        organization_id=str(user.organization_id),
        name=name,
        description=description,
        repository_url=repository_url,
        repository_type=repository_type,
    )

    return {
        "success": True,
        "data": {
            "id": str(project.id),
            "name": project.name,
            "slug": project.slug,
            "description": project.description,
            "repository_url": project.repository_url,
            "repository_type": project.repository_type,
            "organization_id": str(project.organization_id),
            "created_at": project.created_at,
        },
    }


@router.get("/projects")
async def list_projects(
    limit: int = 20,
    offset: int = 0,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all projects for organization"""
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    projects = await list_projects_service(db, str(user.organization_id), limit, offset)
    return {
        "success": True,
        "data": [
            {
                "id": str(project.id),
                "name": project.name,
                "slug": project.slug,
                "description": project.description,
                "repository_url": project.repository_url,
                "repository_type": project.repository_type,
                "created_at": project.created_at,
            }
            for project in projects
        ],
        "pagination": {
            "total": len(projects),
            "limit": limit,
            "offset": offset,
            "has_more": len(projects) == limit,
        },
    }


@router.get("/projects/{project_id}")
async def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get project details"""
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    project = await get_project_service(db, project_id, str(user.organization_id))
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    return {
        "success": True,
        "data": {
            "id": str(project.id),
            "name": project.name,
            "slug": project.slug,
            "description": project.description,
            "repository_url": project.repository_url,
            "repository_type": project.repository_type,
            "organization_id": str(project.organization_id),
            "created_at": project.created_at,
        },
    }


@router.put("/projects/{project_id}")
async def update_project(
    project_id: str,
    name: str | None = None,
    description: str | None = None,
    repository_url: str | None = None,
    repository_type: str | None = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update project"""
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    project = await update_project_service(
        db,
        project_id,
        name=name,
        description=description,
        repository_url=repository_url,
        repository_type=repository_type,
    )
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    return {
        "success": True,
        "data": {
            "id": str(project.id),
            "name": project.name,
            "slug": project.slug,
            "description": project.description,
            "repository_url": project.repository_url,
            "repository_type": project.repository_type,
            "organization_id": str(project.organization_id),
            "created_at": project.created_at,
        },
    }


@router.delete("/projects/{project_id}", status_code=204)
async def delete_project(project_id: str, current_user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Delete project"""
    user_id = current_user.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    deleted = await delete_project_service(db, project_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    return None
