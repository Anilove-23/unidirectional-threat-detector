const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.join(__dirname, '../../.env') });

module.exports = {
  port: parseInt(process.env.PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL || '',
  mongoUri: process.env.MONGODB_URI || '',
  dbType: process.env.DB_TYPE || 'memory',
  alertChannel: process.env.REDIS_ALERT_CHANNEL || 'alert.new',
  flowChannel: process.env.REDIS_FLOW_CHANNEL || 'flow.raw',
};
