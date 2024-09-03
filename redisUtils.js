const redis = require('redis');
const client = redis.createClient({
    url: 'redis://localhost:6379'
});

client.on('error', (err) => {
    console.error('Redis error:', err);
});

async function setValue(key, value) {
    return new Promise((resolve, reject) => {
        client.set(key, value, (err, reply) => {
            if (err) reject(err);
            resolve(reply);
        });
    });
}

async function getValue(key) {
    return new Promise((resolve, reject) => {
        client.get(key, (err, reply) => {
            if (err) reject(err);
            resolve(reply);
        });
    });
}

module.exports = { setValue, getValue };
