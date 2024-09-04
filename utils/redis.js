const redis = require('redis');
const { promisify } = require('util');

class RedisClient {
  constructor() {
    this.client = redis.createClient();
    this.client.on('error', (err) => console.error('Redis error:', err));
    this.get = promisify(this.client.get).bind(this.client);
    this.set = promisify(this.client.set).bind(this.client);
    this.del = promisify(this.client.del).bind(this.client);
  }

  isAlive() {
    return this.client.connected;
  }

  async get(key) {
    return await this.get(key);
  }

  async set(key, value, duration) {
    await this.set(key, value, 'EX', duration);
  }

  async del(key) {
    await this.del(key);
  }
}

const redisClient = new RedisClient();
module.exports = redisClient;
