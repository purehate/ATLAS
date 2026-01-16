import axios from 'axios';
import type { CalculateRequest, CalculateResponse, IndustryInfo } from './types';

// Auto-detect API URL based on current hostname
const getApiUrl = () => {
  // If VITE_API_URL is set, use it
  const envApiUrl = (import.meta as any).env?.VITE_API_URL;
  if (envApiUrl) {
    return envApiUrl;
  }
  
  // Otherwise, use the current hostname with port 6768
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;
  return `${protocol}//${hostname}:6768/api/v1`;
};

const API_URL = getApiUrl();

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const calculateThreats = async (request: CalculateRequest): Promise<CalculateResponse> => {
  const response = await api.post<CalculateResponse>('/calculate', request);
  return response.data;
};

export const getIndustries = async (): Promise<IndustryInfo[]> => {
  const response = await api.get<IndustryInfo[]>('/industries');
  return response.data;
};

export interface CompanySearchResult {
  name: string;
  jurisdiction?: string;
  company_number?: string;
  opencorporates_url?: string;
  registry_url?: string;
  source: string;
}

export interface CompanySearchResponse {
  query: string;
  count: number;
  companies: CompanySearchResult[];
}

export const searchCompanies = async (query: string, limit: number = 10): Promise<CompanySearchResponse> => {
  const response = await api.get<CompanySearchResponse>('/companies/search', {
    params: { q: query, limit }
  });
  return response.data;
};

export const validateCompany = async (name: string): Promise<any> => {
  const response = await api.get('/companies/validate', {
    params: { name }
  });
  return response.data;
};
