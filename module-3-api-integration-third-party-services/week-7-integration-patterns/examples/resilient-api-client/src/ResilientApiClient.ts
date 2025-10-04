import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError, InternalAxiosRequestConfig } from 'axios';
import axiosRetry, { exponentialDelay } from 'axios-retry';
import Bottleneck from 'bottleneck';

// Extend Axios types to include custom properties
declare module 'axios' {
  interface InternalAxiosRequestConfig {
    metadata?: {
      startTime: number;
    };
  }
  
  interface AxiosResponse {
    duration?: number;
  }
}
import { CircuitBreaker, CircuitBreakerConfig } from './CircuitBreaker';

export interface ResilientClientConfig {
  baseURL: string;
  timeout?: number;
  retryConfig?: {
    retries: number;
    retryDelay: number;
    retryCondition?: (error: AxiosError) => boolean;
  };
  circuitBreakerConfig?: CircuitBreakerConfig;
  rateLimitConfig?: {
    maxConcurrent: number;
    minTime: number;
  };
  exponentialDelay?: boolean;
}

export interface ApiResponse<T = any> {
  data: T;
  status: number;
  headers: any;
  duration: number;
  fromCache?: boolean;
}

export class ResilientApiClient {
  private axiosInstance: AxiosInstance;
  private circuitBreaker?: CircuitBreaker;
  private rateLimiter?: Bottleneck;
  private requestCache: Map<string, { data: any; timestamp: number }> = new Map();
  private cacheTimeout: number = 5 * 60 * 1000; // 5 minutes

  constructor(private config: ResilientClientConfig) {
    this.axiosInstance = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout || 10000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'ResilientApiClient/1.0'
      }
    });

    this.setupRetry();
    this.setupCircuitBreaker();
    this.setupRateLimiter();
    this.setupInterceptors();
  }

  private setupRetry(): void {
    if (this.config.retryConfig) {
      axiosRetry(this.axiosInstance, {
        retries: this.config.retryConfig.retries,
        retryDelay: (retryCount) => {
          return retryCount * this.config.retryConfig!.retryDelay;
        },
        retryCondition: this.config.retryConfig.retryCondition || ((error) => {
          return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
                 (error.response?.status || 0) >= 500;
        })
      });
    }
  }

  private setupCircuitBreaker(): void {
    if (this.config.circuitBreakerConfig) {
      this.circuitBreaker = new CircuitBreaker(this.config.circuitBreakerConfig);
    }
  }

  private setupRateLimiter(): void {
    if (this.config.rateLimitConfig) {
      this.rateLimiter = new Bottleneck({
        maxConcurrent: this.config.rateLimitConfig.maxConcurrent,
        minTime: this.config.rateLimitConfig.minTime
      });
    }
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.axiosInstance.interceptors.request.use(
      (config) => {
        config.metadata = { startTime: Date.now() };
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.axiosInstance.interceptors.response.use(
      (response) => {
        if (response.config.metadata) {
          const duration = Date.now() - response.config.metadata.startTime;
          response.duration = duration;
        }
        return response;
      },
      (error) => {
        if (error.config?.metadata) {
          error.duration = Date.now() - error.config.metadata.startTime;
        }
        return Promise.reject(error);
      }
    );
  }

  private getCacheKey(method: string, url: string, params?: any): string {
    return `${method}:${url}:${JSON.stringify(params || {})}`;
  }

  private getFromCache<T>(cacheKey: string): T | null {
    const cached = this.requestCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    if (cached) {
      this.requestCache.delete(cacheKey);
    }
    return null;
  }

  private setCache(cacheKey: string, data: any): void {
    this.requestCache.set(cacheKey, {
      data,
      timestamp: Date.now()
    });
  }

  private async executeRequest<T>(operation: () => Promise<AxiosResponse<T>>): Promise<ApiResponse<T>> {
    const execute = async (): Promise<ApiResponse<T>> => {
      const response = await operation();
      return {
        data: response.data,
        status: response.status,
        headers: response.headers,
        duration: (response as any).duration || 0
      };
    };

    if (this.rateLimiter) {
      return this.rateLimiter.schedule(execute);
    }

    if (this.circuitBreaker) {
      return this.circuitBreaker.execute(execute);
    }

    return execute();
  }

  async get<T = any>(url: string, config?: AxiosRequestConfig & { useCache?: boolean }): Promise<ApiResponse<T>> {
    const cacheKey = this.getCacheKey('GET', url, config?.params);
    
    // Check cache first
    if (config?.useCache !== false) {
      const cached = this.getFromCache<T>(cacheKey);
      if (cached) {
        return {
          data: cached,
          status: 200,
          headers: {},
          duration: 0,
          fromCache: true
        };
      }
    }

    const result = await this.executeRequest<T>(() => 
      this.axiosInstance.get(url, config)
    );

    // Cache successful GET requests
    if (result.status === 200 && config?.useCache !== false) {
      this.setCache(cacheKey, result.data);
    }

    return result;
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeRequest<T>(() => 
      this.axiosInstance.post(url, data, config)
    );
  }

  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeRequest<T>(() => 
      this.axiosInstance.put(url, data, config)
    );
  }

  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeRequest<T>(() => 
      this.axiosInstance.delete(url, config)
    );
  }

  async patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<ApiResponse<T>> {
    return this.executeRequest<T>(() => 
      this.axiosInstance.patch(url, data, config)
    );
  }

  // Health check method
  async healthCheck(): Promise<{ healthy: boolean; latency: number; circuitBreakerState?: string }> {
    const startTime = Date.now();
    
    try {
      await this.get('/');
      const latency = Date.now() - startTime;
      
      return {
        healthy: true,
        latency,
        circuitBreakerState: this.circuitBreaker?.getState()
      };
    } catch (error) {
      return {
        healthy: false,
        latency: Date.now() - startTime,
        circuitBreakerState: this.circuitBreaker?.getState()
      };
    }
  }

  // Get circuit breaker metrics
  getCircuitBreakerMetrics() {
    return this.circuitBreaker?.getMetrics();
  }

  // Get circuit breaker state
  getCircuitBreakerState() {
    return this.circuitBreaker?.getState() || 'CLOSED';
  }

  // Reset circuit breaker
  resetCircuitBreaker(): void {
    this.circuitBreaker?.reset();
  }

  // Clear cache
  clearCache(): void {
    this.requestCache.clear();
  }

  // Get cache stats
  getCacheStats() {
    return {
      size: this.requestCache.size,
      keys: Array.from(this.requestCache.keys())
    };
  }
}
