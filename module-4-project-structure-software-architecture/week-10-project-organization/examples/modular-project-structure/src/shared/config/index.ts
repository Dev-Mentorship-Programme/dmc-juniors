// Shared configuration management
export interface AppConfig {
  port: number;
  nodeEnv: string;
  logLevel: string;
}

export const config: AppConfig = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  logLevel: process.env.LOG_LEVEL || 'info',
};
