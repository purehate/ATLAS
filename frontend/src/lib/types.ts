export interface CalculateRequest {
  company_name: string;
  business_vertical: string;
  sub_vertical?: string;
}

export interface TechniqueInfo {
  id: string;
  technique_id: string;
  name: string;
  tactic: string;
}

export interface TechniqueScore {
  technique: TechniqueInfo;
  score: number;
  evidence_count: number;
}

export interface ThreatActorInfo {
  id: string;
  name: string;
  aliases: string[];
  mitre_id?: string;
}

export interface Explanation {
  source_title: string;
  source_url: string;
  source_date: string;
  excerpt?: string;
}

export interface ActorResult {
  threat_actor_group: ThreatActorInfo;
  confidence: string;
  weighted_score: number;
  top_techniques: TechniqueScore[];
  explanations: Explanation[];
}

export interface BreachDetection {
  status: 'none' | 'low' | 'medium' | 'high';
  confidence: number;
  articles: Array<{
    type: string;
    source: string;
    title: string;
    url: string;
    date: string;
    confidence: number;
    excerpt?: string;
  }>;
  article_count: number;
  last_updated: string;
  message?: string;
}

export interface CalculateResponse {
  request_id: string;
  industry_id?: string;
  results: ActorResult[];
  metadata: {
    calculated_at: string;
    total_evidence_items?: number;
    sources_used?: string[];
    message?: string;
    breach_detection?: BreachDetection;
  };
}

export interface IndustryInfo {
  id: string;
  name: string;
  code: string;
  parent_id?: string;
}
