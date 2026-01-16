"""Initial migration

Revision ID: 001_initial
Revises: 
Create Date: 2024-01-20 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create industries table
    op.create_table(
        'industries',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False, unique=True),
        sa.Column('code', sa.String(50), nullable=False, unique=True),
        sa.Column('parent_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.Date(), nullable=False),
        sa.Column('updated_at', sa.Date(), nullable=False),
        sa.ForeignKeyConstraint(['parent_id'], ['industries.id']),
    )
    op.create_index('ix_industries_name', 'industries', ['name'])
    
    # Create threat_actor_groups table
    op.create_table(
        'threat_actor_groups',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False, unique=True),
        sa.Column('aliases', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('mitre_id', sa.String(50), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.Date(), nullable=True),
        sa.Column('last_seen', sa.Date(), nullable=True),
        sa.Column('meta_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.Date(), nullable=False),
        sa.Column('updated_at', sa.Date(), nullable=False),
    )
    op.create_index('ix_threat_actor_groups_name', 'threat_actor_groups', ['name'])
    op.create_index('ix_threat_actor_groups_mitre_id', 'threat_actor_groups', ['mitre_id'])
    
    # Create mitre_techniques table
    op.create_table(
        'mitre_techniques',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('technique_id', sa.String(50), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('tactic', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('url', sa.String(500), nullable=True),
        sa.Column('meta_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.Date(), nullable=False),
        sa.Column('updated_at', sa.Date(), nullable=False),
    )
    op.create_index('ix_mitre_techniques_technique_id', 'mitre_techniques', ['technique_id'])
    op.create_index('ix_mitre_techniques_tactic', 'mitre_techniques', ['tactic'])
    
    # Create sources table
    op.create_table(
        'sources',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('base_url', sa.String(500), nullable=True),
        sa.Column('reliability_score', sa.Integer(), nullable=False),
        sa.Column('last_checked_at', sa.Date(), nullable=True),
        sa.Column('meta_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.Date(), nullable=False),
        sa.Column('updated_at', sa.Date(), nullable=False),
    )
    op.create_index('ix_sources_name', 'sources', ['name'])
    
    # Create evidence_items table
    op.create_table(
        'evidence_items',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('threat_actor_group_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('industry_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('technique_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('source_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source_url', sa.String(1000), nullable=False),
        sa.Column('source_title', sa.String(500), nullable=True),
        sa.Column('source_date', sa.Date(), nullable=False),
        sa.Column('excerpt', sa.Text(), nullable=True),
        sa.Column('confidence_score', sa.Integer(), nullable=True),
        sa.Column('meta_data', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.Date(), nullable=False),
        sa.Column('updated_at', sa.Date(), nullable=False),
        sa.ForeignKeyConstraint(['threat_actor_group_id'], ['threat_actor_groups.id']),
        sa.ForeignKeyConstraint(['industry_id'], ['industries.id']),
        sa.ForeignKeyConstraint(['technique_id'], ['mitre_techniques.id']),
        sa.ForeignKeyConstraint(['source_id'], ['sources.id']),
    )
    op.create_index('idx_evidence_actor_industry_tech', 'evidence_items', 
                    ['threat_actor_group_id', 'industry_id', 'technique_id'])
    op.create_index('idx_evidence_source_date', 'evidence_items', ['source_date'])
    
    # Create actor_industry_scores table
    op.create_table(
        'actor_industry_scores',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('threat_actor_group_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('industry_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('total_evidence_count', sa.Integer(), nullable=False),
        sa.Column('weighted_score', sa.Float(), nullable=False),
        sa.Column('last_calculated_at', sa.Date(), nullable=False),
        sa.ForeignKeyConstraint(['threat_actor_group_id'], ['threat_actor_groups.id']),
        sa.ForeignKeyConstraint(['industry_id'], ['industries.id']),
        sa.UniqueConstraint('threat_actor_group_id', 'industry_id', name='uq_actor_industry'),
    )
    op.create_index('idx_actor_industry_score', 'actor_industry_scores', 
                    ['industry_id', 'weighted_score'])
    
    # Create actor_technique_scores table
    op.create_table(
        'actor_technique_scores',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('threat_actor_group_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('technique_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('industry_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('evidence_count', sa.Integer(), nullable=False),
        sa.Column('weighted_score', sa.Float(), nullable=False),
        sa.Column('last_calculated_at', sa.Date(), nullable=False),
        sa.ForeignKeyConstraint(['threat_actor_group_id'], ['threat_actor_groups.id']),
        sa.ForeignKeyConstraint(['technique_id'], ['mitre_techniques.id']),
        sa.ForeignKeyConstraint(['industry_id'], ['industries.id']),
        sa.UniqueConstraint('threat_actor_group_id', 'technique_id', 'industry_id', 
                          name='uq_actor_technique_industry'),
    )
    op.create_index('idx_actor_technique_score', 'actor_technique_scores', 
                    ['threat_actor_group_id', 'industry_id', 'weighted_score'])


def downgrade() -> None:
    op.drop_table('actor_technique_scores')
    op.drop_table('actor_industry_scores')
    op.drop_table('evidence_items')
    op.drop_table('sources')
    op.drop_table('mitre_techniques')
    op.drop_table('threat_actor_groups')
    op.drop_table('industries')
