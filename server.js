
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const os = require('os');
const archiver = require('archiver');
const { randomUUID } = require('crypto');
const http = require('http');
const { Server } = require('socket.io');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

// --- কনফিগারেশন এবং ধ্রুবক ---
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_please_change';
const MONGODB_URI = process.env.MONGODB_URI;

// টাইমিং কনফিগারেশন
const BATCH_INTERVAL_MS = 10000;       // ১০ সেকেন্ড
const DEVICE_SYNC_INTERVAL_MS = 600000; // ১০ মিনিট
const OFFLINE_CHECK_INTERVAL_MS = 60000; // ১ মিনিট
const OFFLINE_THRESHOLD_MS = 3600000;    // ৬০ মিনিট

// গ্লোবাল ভেরিয়েবল     
let db;
let espDataBuffer = [];
const backupJobs = new Map();

// --- অ্যাপ ইনিশিয়ালাইজেশন ---
const app = express();
const http_server = http.createServer(app);
const io = new Server(http_server, {
    cors: { origin: "*" } // Socket.io CORS
});   

// --- ইমেইল ট্রান্সপোর্টার ---bhh
let mailTransporter;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    mailTransporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.EMAIL_PORT || '587'),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });
    console.log('[Email] ইমেইল সিস্টেম সক্রিয় আছে।');
} else {
    console.warn('[Email] ইমেইল কনফিগারেশন পাওয়া যায়নি।');
}

// --- মিডলওয়্যার ---
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(compression());
app.use(cors({
    origin: true,
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'token']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ডাটাবেস অ্যাটাচমেন্ট মিডলওয়্যার (খুবই গুরুত্বপূর্ণ)
app.use((req, res, next) => {
    if (!db) return res.status(503).send({ message: 'Database connecting...' });
    req.db = db;
    next();
});

// --- অথেন্টিকেশন মিডলওয়্যার ---
const authenticateJWT = (req, res, next) => {
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    } else if (req.query && req.query.token) {
        token = req.query.token;
    }

    if (!token) return res.status(401).send({ success: false, message: 'Authorization token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// --- অ্যাডমিন চেক হেল্পার ---
const ensureAdmin = async (req, res, next) => {
    try {
        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        const isAdminEnv = process.env.ADMIN_EMAIL && user && user.email === process.env.ADMIN_EMAIL;
        
        if (user && (user.isAdmin === true || isAdminEnv)) {
            req.userData = user; // পরবর্তী ব্যবহারের জন্য
            next();
        } else {
            res.status(403).send({ success: false, message: 'Admin access required' });
        }
    } catch (error) {
        res.status(500).send({ success: false, message: 'Internal server error during admin check' });
    }
};

// --- হেল্পার ফাংশন: কাস্টম ডেট পার্সার ---
// এখন থেকে এই ফাংশন শুধুমাত্র dateTime স্ট্রিংটি সরাসরি timestamp হিসেবে ব্যবহার করবে
function parseAndAssignTimestamp(data) {
    // 1. dateTime ফিল্ডকে timestamp হিসেবে ব্যবহার করা
    if (data.dateTime && typeof data.dateTime === 'string') {
        data.timestamp = data.dateTime;
    } 
    // 2. যদি dateTime না থাকে, তবে সার্ভারের বর্তমান সময়কে Date অবজেক্ট হিসেবে ব্যবহার করা
    else {
        data.timestamp = new Date();
    }
    
    // 3. সার্ভার কখন ডেটা পেয়েছে তার সময়
    data.receivedAt = new Date();
    
    return data;
}


// ------------------------------
// --- ব্যাকগ্রাউন্ড প্রসেস ---
// ------------------------------

// ১. ব্যাচ ডাটা ইনসার্ট এবং রিয়েল-টাইম আপডেট
async function processDataBuffer() {
    if (espDataBuffer.length === 0 || !db) return;

    const dataToInsert = [...espDataBuffer];
    espDataBuffer = []; // বাফার খালি করা

    const espCollection = db.collection('espdata2');
    const devicesCollection = db.collection('devices');

    try {
        // বাল্ক ইনসার্ট
        await espCollection.insertMany(dataToInsert, { ordered: false });
        
        // সকেটে নতুন ডাটা পাঠানো
        io.emit('new-data', dataToInsert);

        // ডিভাইসের লাস্ট সিন এবং স্ট্যাটাস আপডেট
        const bulkUpdates = [];
        const uniqueDevices = new Map();

        // ডুপ্লিকেট এড়িয়ে লেটেস্ট ডাটা বের করা
        dataToInsert.forEach(d => {
            if (d.uid) {
                // receivedAt ব্যবহার করা হচ্ছে, কারণ timestamp এখন স্ট্রিং
                const ts = new Date(d.receivedAt);
                if (!uniqueDevices.has(d.uid) || ts > new Date(uniqueDevices.get(d.uid).receivedAt)) {
                    uniqueDevices.set(d.uid, d);
                }
            }
        });

        uniqueDevices.forEach((data, uid) => {
            // নতুন JSON স্ট্রাকচার অনুযায়ী ডাটা ম্যাপ করা
            const deviceData = {
                version: data.version,
                pssensor: data.pssensor || {},     // { cable, mpa, avg_mpa, depth_ft }
                environment: data.environment || {}, // { temp, hum }
                rain: data.rain || {},             // { count, mm }
                
                // --- Backward Compatibility (যাতে আগের ফ্রন্টএন্ড না ভাঙ্গে) ---
                temperature: (data.environment && data.environment.temp !== undefined) ? data.environment.temp : data.temperature,
                humidity: (data.environment && data.environment.hum !== undefined) ? data.environment.hum : null,
                water_level: (data.pssensor && data.pssensor.depth_ft !== undefined) ? data.pssensor.depth_ft : data.water_level,
                rainfall: (data.rain && data.rain.mm !== undefined) ? data.rain.mm : data.rainfall
            };

            bulkUpdates.push({
                updateOne: {
                    filter: { uid: uid },
                    update: {
                        $set: {
                            lastSeen: data.receivedAt, // lastSeen এখন Date অবজেক্ট
                            status: 'online',
                            data: deviceData
                        },
                        $setOnInsert: {
                            addedAt: new Date(),
                            location: null,
                            name: `Device-${uid}`
                        }
                    },
                    upsert: true
                }
            });
        });

        if (bulkUpdates.length > 0) {
            await devicesCollection.bulkWrite(bulkUpdates, { ordered: false });
            io.emit('device-status-updated', Array.from(uniqueDevices.keys()));
        }
        
        // console.log(`[Batch] ${dataToInsert.length} records processed.`);

    } catch (error) {
        if (error.code !== 11000) { // Ignore duplicate key errors
             console.error('[Batch Error]', error.message);
        }
    }
}

// ২. অফলাইন চেকার
async function checkOfflineDevices() {
    if (!db) return;
    try {
        const threshold = new Date(Date.now() - OFFLINE_THRESHOLD_MS);
        const devicesCollection = db.collection('devices');

        const offlineDevices = await devicesCollection.find(
             { status: 'online', lastSeen: { $lt: threshold } },
             { projection: { uid: 1, _id: 0 } }
        ).toArray();

        if (offlineDevices.length > 0) {
            const uidsToUpdate = offlineDevices.map(d => d.uid);
            const result = await devicesCollection.updateMany(
                { uid: { $in: uidsToUpdate } },
                { $set: { status: 'offline' } }
            );

            if (result.modifiedCount > 0) {
                console.log(`[Offline Monitor] ${result.modifiedCount} devices marked offline.`);
                io.emit('device-status-updated', uidsToUpdate);
            }
        }
    } catch (error) {
        console.error('[Offline Monitor Error]', error);
    }
}

// ৩. পুরনো ব্যাকআপ ক্লিনআপ
function cleanupBackups() {
    const NOW = Date.now();
    backupJobs.forEach((job, id) => {
        if ((job.status === 'done' || job.status === 'error') && (NOW - job.finishedAt > 3600000)) {
            if (job.tmpDir) {
                fs.rm(job.tmpDir, { recursive: true, force: true }, (err) => {
                    if (err) console.error(`Failed to clean up backup directory: ${job.tmpDir}`, err);
                });
            }
            backupJobs.delete(id);
        }
    });
}

// ------------------------------
// --- রাউটস (Routes) ---
// ------------------------------

// ১. IoT ডাটা রিসিভার রাউটস
const iotRouter = express.Router();

// ডিভাইসের জন্য ওয়াটার লেভেলের অফসেট ট্র্যাকিং
const waterLevelOffsets = {};

const processIncomingData = (data) => {
    const uid = data.uid || 'unknown';
    
    // যদি ডিভাইসের জন্য আগে থেকে অফসেট না থাকে, তবে ০ থেকে শুরু করি
    if (waterLevelOffsets[uid] === undefined) {
        waterLevelOffsets[uid] = 0;
    }

    // প্রতিবার ডাটা আসার সময় কিছুটা রেন্ডম ড্রিফট (drift) যোগ করা হবে (-0.5 থেকে +0.5 ফুট)
    let drift = (Math.random() * 1.0) - 0.5;
    waterLevelOffsets[uid] += drift;

    // টোটাল অফসেট যেন -3 ফুট থেকে +3 ফুটের মধ্যে থাকে (যাতে ১-৩ ফুট কম-বেশি হয়)
    if (waterLevelOffsets[uid] > 3) waterLevelOffsets[uid] = 3;
    if (waterLevelOffsets[uid] < -3) waterLevelOffsets[uid] = -3;

    // পিসেন্সরের (pssensor) ডেটা আপডেট
    if (data.pssensor && data.pssensor.depth_ft !== undefined) {
        let current = parseFloat(data.pssensor.depth_ft);
        if (!isNaN(current)) {
            data.pssensor.depth_ft = Math.max(0, current + waterLevelOffsets[uid]);
            data.pssensor.depth_ft = Math.round(data.pssensor.depth_ft * 100) / 100;
        }
    }
    
    // মেইন water_level প্রপার্টি আপডেট
    if (data.water_level !== undefined) {
        let current = parseFloat(data.water_level);
        if (!isNaN(current)) {
            data.water_level = Math.max(0, current + waterLevelOffsets[uid]);
            data.water_level = Math.round(data.water_level * 100) / 100;
        }
    }

    const processedData = parseAndAssignTimestamp(data);
    espDataBuffer.push(processedData);
};


iotRouter.post('/esp32pp', (req, res) => { // UTC রিসিভার
    processIncomingData(req.body);
    res.status(200).send({ message: 'Queued (UTC)' });
});

iotRouter.post('/esp32p', (req, res) => { // BD Time Zone হ্যান্ডলার
    processIncomingData(req.body);
    res.status(200).send({ message: 'Queued (BDT)' });
});

// ২. পাবলিক ডাটা API
const publicRouter = express.Router();

publicRouter.post('/device/data-by-range', authenticateJWT, async (req, res) => {
    try {
        console.log('[data-by-range Request Body]:', JSON.stringify(req.body));
        const { uid, start, end, limit } = req.body || {};
        if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });

        // ফিল্টারিং এর জন্য receivedAt (Date object) ব্যবহার করা হচ্ছে
        const query = { uid: String(uid) };
        if (start || end) {
            query.receivedAt = {};
            const parseDateParam = (str, isEnd = false) => {
                if (!str) return null;
                let s = String(str).trim();
                if (!s) return null;
                if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
                    s = isEnd ? `${s}T23:59:59.999+06:00` : `${s}T00:00:00.000+06:00`;
                } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)) {
                    s = isEnd ? `${s}:59.999+06:00` : `${s}:00.000+06:00`;
                } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(s)) {
                    s = isEnd ? `${s}.999+06:00` : `${s}.000+06:00`;
                }
                const d = new Date(s);
                return isNaN(d.getTime()) ? null : d;
            };

            if (start) {
                const startDate = parseDateParam(start, false);
                if (startDate) {
                    query.receivedAt.$gte = startDate;
                } else {
                    return res.status(400).send({ success: false, message: 'Invalid start date format' });
                }
            }
            if (end) {
                const endDate = parseDateParam(end, true);
                if (endDate) {
                    query.receivedAt.$lte = endDate;
                } else {
                    return res.status(400).send({ success: false, message: 'Invalid end date format' });
                }
            }
            if (Object.keys(query.receivedAt).length === 0) {
                delete query.receivedAt;
            }
        }
        
        let docs;
        const projection = {
            _id: 1,
            uid: 1,
            pssensor: 1,
            environment: 1,
            rain: 1,
            timestamp: 1,
            dateTime: 1,
            temperature: 1,
            water_level: 1,
            rainfall: 1,
            humidity: 1,
            receivedAt: 1
        };

        if (query.receivedAt) {
            // ডেট ফিল্টার অনুযায়ী সব স্টেপ-বাই-স্টেপ ডাটা সরাসরি ফেচ করা হবে (সম্পূর্ণ নিখুঁত ডাটা)
            const cursor = req.db.collection('espdata2').find(query, { projection })
              .sort({ receivedAt: 1 });
            
            const numLimit = parseInt(limit, 10);
            if (!isNaN(numLimit) && numLimit > 0 && limit !== 'all') {
                cursor.limit(numLimit);
            } else {
                cursor.limit(150000); // Support up to 3+ years of 15-minute readings without truncation
            }
            docs = await cursor.toArray();
        } else {
            // ডেট ফিল্টার না থাকলে লেটেস্ট ডাটা নেওয়া হবে এবং ক্রমানুসারে সাজানো হবে
            const numLimit = parseInt(limit, 10);
            const lim = (!isNaN(numLimit) && numLimit > 0) ? numLimit : 5000;
            docs = await req.db.collection('espdata2').find(query, { projection })
              .sort({ receivedAt: -1 })
              .limit(lim)
              .toArray();
            docs.reverse();
        }

        return res.send(docs);
    } catch (error) {
        console.error('Error in /data-by-range:', error);
        return res.status(500).send({ success: false, message: 'Server error' });
    }
});

publicRouter.put('/device/data/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        const { temperature, humidity, water_level, rainfall } = req.body;
        
        if (!ObjectId.isValid(id)) return res.status(400).send({ success: false, message: 'Invalid ID' });

        const updateFields = {};
        if (temperature !== undefined) updateFields['environment.temp'] = parseFloat(temperature);
        if (humidity !== undefined) updateFields['environment.hum'] = parseFloat(humidity);
        if (water_level !== undefined) updateFields['pssensor.depth_ft'] = parseFloat(water_level);
        if (rainfall !== undefined) updateFields['rain.mm'] = parseFloat(rainfall);
        
        // Also update backward compatibility fields
        if (temperature !== undefined) updateFields['temperature'] = parseFloat(temperature);
        if (humidity !== undefined) updateFields['humidity'] = parseFloat(humidity);
        if (water_level !== undefined) updateFields['water_level'] = parseFloat(water_level);
        if (rainfall !== undefined) updateFields['rainfall'] = parseFloat(rainfall);

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).send({ success: false, message: 'No fields to update.' });
        }

        const result = await req.db.collection('espdata2').updateOne(
            { _id: new ObjectId(id) },
            { $set: updateFields }
        );

        if (result.matchedCount === 0) {
            return res.status(404).send({ success: false, message: 'Record not found.' });
        }
        res.send({ success: true, message: 'Data updated successfully.' });
    } catch (error) {
        console.error('Error updating data:', error);
        res.status(500).send({ success: false, message: 'Internal server error' });
    }
});

publicRouter.delete('/device/data/:id', authenticateJWT, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).send({ success: false, message: 'Invalid ID' });

        const doc = await req.db.collection('espdata2').findOne({ _id: new ObjectId(id) });
        if (!doc) return res.status(404).send({ success: false, message: 'Record not found.' });

        await req.db.collection('trash').insertOne({
            type: 'telemetry',
            originalId: doc._id,
            document: doc,
            deletedBy: req.user.userId,
            deletedAt: new Date()
        });

        await req.db.collection('espdata2').deleteOne({ _id: new ObjectId(id) });

        res.send({ success: true, message: 'Data moved to trash.' });
    } catch (error) {
        console.error('Error deleting data:', error);
        res.status(500).send({ success: false, message: 'Internal server error' });
    }
});

publicRouter.post('/device/rain/summary', authenticateJWT, async (req, res) => {
    try {
        const { uid, start, end } = req.body;
        if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });

        const query = { uid: String(uid) };
        if (start && end) {
            const startDate = new Date(start);
            const endDate = new Date(end);
            if (!isNaN(startDate.getTime()) && !isNaN(endDate.getTime())) {
                query.receivedAt = { $gte: startDate, $lte: endDate };
            }
        }

        const result = await req.db.collection('espdata2').aggregate([
            { $match: query },
            { $group: {
                _id: null,
                totalRain: { $sum: { $ifNull: ["$rain.mm", { $ifNull: ["$rainfall", 0] }] } },
                count: { $sum: 1 }
            }}
        ]).toArray();

        const data = result.length > 0 ? result[0] : { totalRain: 0, count: 0 };
        // Round totalRain to 2 decimal places
        data.totalRain = Math.round(data.totalRain * 100) / 100;
        
        res.send({ success: true, ...data });
    } catch (error) {
        console.error('Error in /device/rain/summary:', error);
        res.status(500).send({ success: false, message: 'Server error' });
    }
});

publicRouter.post('/device/rain/distribute', authenticateJWT, async (req, res) => {
    try {
        const { uid, start, end, totalRain } = req.body;
        if (!uid || totalRain === undefined) {
            return res.status(400).send({ success: false, message: 'uid and totalRain are required' });
        }

        const targetRain = parseFloat(totalRain);
        if (isNaN(targetRain) || targetRain < 0) {
             return res.status(400).send({ success: false, message: 'Invalid totalRain value' });
        }

        const query = { uid: String(uid) };
        if (start && end) {
            const startDate = new Date(start);
            const endDate = new Date(end);
            if (!isNaN(startDate.getTime()) && !isNaN(endDate.getTime())) {
                query.receivedAt = { $gte: startDate, $lte: endDate };
            }
        }

        const docs = await req.db.collection('espdata2').find(query).project({ _id: 1 }).toArray();
        if (docs.length === 0) {
            return res.status(404).send({ success: false, message: 'No records found in this date range to distribute rain.' });
        }

        // Randomly distribute targetRain across docs
        const weights = docs.map(() => Math.random());
        const totalWeight = weights.reduce((acc, val) => acc + val, 0);

        const bulkOps = [];
        let distributedSoFar = 0;

        for (let i = 0; i < docs.length; i++) {
            let rainForThisDoc;
            if (i === docs.length - 1) {
                // Ensure exact total for the last one (avoid rounding errors)
                rainForThisDoc = Math.max(0, targetRain - distributedSoFar);
                rainForThisDoc = Math.round(rainForThisDoc * 100) / 100;
            } else {
                rainForThisDoc = (weights[i] / totalWeight) * targetRain;
                rainForThisDoc = Math.round(rainForThisDoc * 100) / 100; // Round to 2 decimal places
                distributedSoFar += rainForThisDoc;
            }

            bulkOps.push({
                updateOne: {
                    filter: { _id: docs[i]._id },
                    update: {
                        $set: {
                            'rain.mm': rainForThisDoc,
                            'rainfall': rainForThisDoc
                        }
                    }
                }
            });
        }

        if (bulkOps.length > 0) {
            await req.db.collection('espdata2').bulkWrite(bulkOps, { ordered: false });
        }

        res.send({ success: true, message: `Successfully distributed ${targetRain} mm rain across ${docs.length} records.` });
    } catch (error) {
        console.error('Error in /device/rain/distribute:', error);
        res.status(500).send({ success: false, message: 'Server error' });
    }
});

publicRouter.post('/device/waterlevel/randomize', authenticateJWT, async (req, res) => {
    try {
        const { uid, start, end, minFt, maxFt } = req.body;
        if (!uid || minFt === undefined || maxFt === undefined) {
            return res.status(400).send({ success: false, message: 'uid, minFt, and maxFt are required' });
        }

        const min = parseFloat(minFt);
        const max = parseFloat(maxFt);
        
        if (isNaN(min) || isNaN(max) || min > max) {
             return res.status(400).send({ success: false, message: 'Invalid minFt/maxFt values' });
        }

        const query = { uid: String(uid) };
        if (start && end) {
            const startDate = new Date(start);
            const endDate = new Date(end);
            if (!isNaN(startDate.getTime()) && !isNaN(endDate.getTime())) {
                query.receivedAt = { $gte: startDate, $lte: endDate };
            }
        }

        const docs = await req.db.collection('espdata2').find(query).project({ _id: 1 }).toArray();
        if (docs.length === 0) {
            return res.status(404).send({ success: false, message: 'No records found in this date range.' });
        }

        const bulkOps = [];

        for (let i = 0; i < docs.length; i++) {
            let randomLevel = (Math.random() * (max - min)) + min;
            randomLevel = Math.round(randomLevel * 100) / 100;

            bulkOps.push({
                updateOne: {
                    filter: { _id: docs[i]._id },
                    update: {
                        $set: {
                            'pssensor.depth_ft': randomLevel,
                            'water_level': randomLevel
                        }
                    }
                }
            });
        }

        if (bulkOps.length > 0) {
            await req.db.collection('espdata2').bulkWrite(bulkOps, { ordered: false });
        }

        res.send({ success: true, message: `Successfully assigned random water levels (${min} - ${max} ft) across ${docs.length} records.` });
    } catch (error) {
        console.error('Error in /device/waterlevel/randomize:', error);
        res.status(500).send({ success: false, message: 'Server error' });
    }
});

publicRouter.post('/device/sync-historical', authenticateJWT, async (req, res) => {
    try {
        const { uid, startDate, endDate } = req.body;
        if (!uid) {
            return res.status(400).send({ success: false, message: 'uid is required' });
        }

        // Open-Meteo Archive is delayed. Safest max date is 2 days ago.
        const maxAllowedDate = new Date(new Date().getTime() - 2 * 86400000);
        
        let end = endDate ? new Date(endDate) : maxAllowedDate;
        if (end > maxAllowedDate) {
            end = maxAllowedDate;
        }

        let start = startDate ? new Date(startDate) : new Date(end.getTime() - 7 * 86400000);
        if (start > end) {
            start = new Date(end.getTime() - 86400000); // fallback to 1 day before end
        }

        // Limit to maximum 2 years (730 days) of data
        const MAX_DAYS = 730;
        const diffDays = (end.getTime() - start.getTime()) / 86400000;
        if (diffDays > MAX_DAYS) {
            start = new Date(end.getTime() - MAX_DAYS * 86400000);
        }

        if (isNaN(start.getTime()) || isNaN(end.getTime())) {
            return res.status(400).send({ success: false, message: 'Invalid start or end date' });
        }

        // 1. Get device info
        const device = await req.db.collection('devices').findOne({ uid: String(uid) });
        if (!device) {
            return res.status(404).send({ success: false, message: 'Device not found' });
        }

        if (!device.latitude || !device.longitude) {
            return res.status(400).send({ success: false, message: 'Device does not have latitude/longitude set' });
        }

        const lat = device.latitude;
        const lon = device.longitude;
        const baseWaterLevel = device.water_level || 0; // fallback to 0 if not set

        // 2. Format dates for Open-Meteo (YYYY-MM-DD)
        const startStr = start.toISOString().split('T')[0];
        const endStr = end.toISOString().split('T')[0];

        // 3. Fetch data from Open-Meteo Archive API
        const apiUrl = `https://archive-api.open-meteo.com/v1/archive?latitude=${lat}&longitude=${lon}&start_date=${startStr}&end_date=${endStr}&hourly=temperature_2m,relative_humidity_2m,rain&timezone=auto`;
        
        const response = await fetch(apiUrl);
        if (!response.ok) {
            const errText = await response.text();
            console.error('Open-Meteo API Error:', errText);
            try {
                const parsed = JSON.parse(errText);
                return res.status(400).send({ success: false, message: 'Open-Meteo Error: ' + (parsed.reason || 'Failed to fetch data') });
            } catch(e) {
                return res.status(500).send({ success: false, message: 'Failed to fetch historical weather data' });
            }
        }

        const data = await response.json();
        
        if (!data.hourly || !data.hourly.time) {
            return res.status(500).send({ success: false, message: 'Invalid response from weather API' });
        }

        // 4. Delete existing data for this uid and date range to avoid duplicates
        await req.db.collection('espdata2').deleteMany({
            uid: String(uid),
            receivedAt: { $gte: start, $lte: new Date(end.getTime() + 86400000) } // include the whole end day
        });

        // 5. Generate telemetry data
        const recordsToInsert = [];
        const times = data.hourly.time;
        const temps = data.hourly.temperature_2m;
        const hums = data.hourly.relative_humidity_2m;
        const rains = data.hourly.rain;
        
        // 1 hour = 4 records of 15 min.
        const totalExpectedRecords = times.length * 4;

        for (let i = 0; i < times.length; i++) {
            const timeStr = times[i];
            const baseDateObj = new Date(timeStr);
            
            const temp = temps[i] !== null ? temps[i] : 25.0; // fallback
            const hum = hums[i] !== null ? hums[i] : 60.0;
            const rain = rains[i] !== null ? rains[i] : 0.0;

            for (let m = 0; m < 4; m++) {
                const dateObj = new Date(baseDateObj.getTime() + m * 15 * 60000);

                // Generate randomized water level based on base level
                const fluctuation = (Math.random() * 1) - 0.5; // -0.5 to +0.5
                let calcWaterLevel = baseWaterLevel + fluctuation;
                if (rain > 0) {
                    calcWaterLevel += (rain * 0.1); // slight increase based on rain
                }
                calcWaterLevel = Math.round(calcWaterLevel * 100) / 100;
                if (calcWaterLevel < 0) calcWaterLevel = 0;

                const doc = {
                    uid: String(uid),
                    receivedAt: dateObj,
                    timestamp: dateObj.toISOString(),
                    dateTime: dateObj.toISOString(),
                    version: "1.0",
                    environment: { temp: temp, hum: hum },
                    rain: { mm: rain },
                    pssensor: { depth_ft: calcWaterLevel },
                    temperature: temp,
                    humidity: hum,
                    rainfall: rain,
                    water_level: calcWaterLevel
                };
                
                recordsToInsert.push(doc);
            }
        }

        // 6. Insert data in batches and emit progress
        const batchSize = 96; // 1 day worth of 15-min data
        let insertedCount = 0;

        if (recordsToInsert.length > 0) {
            for (let i = 0; i < recordsToInsert.length; i += batchSize) {
                const batch = recordsToInsert.slice(i, i + batchSize);
                await req.db.collection('espdata2').insertMany(batch, { ordered: false });
                insertedCount += batch.length;
                
                const percent = Math.round((insertedCount / totalExpectedRecords) * 100);
                // Emit progress via Socket.io
                io.emit('sync_progress', { 
                    uid: String(uid), 
                    percent: percent, 
                    current: insertedCount, 
                    total: totalExpectedRecords 
                });
                
                // Small delay to allow the event loop to process other requests and UI to update
                await new Promise(r => setTimeout(r, 50));
            }
        }

        res.send({ 
            success: true, 
            message: `Successfully synchronized and generated ${recordsToInsert.length} historical records.`,
            count: recordsToInsert.length
        });

    } catch (error) {
        console.error('Error in /device/sync-historical:', error);
        res.status(500).send({ success: false, message: 'Server error during historical sync' });
    }
});


// ৩. অথেন্টিকেশন রাউটস
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).send({ message: 'All fields required' });
        
        const users = req.db.collection('users');
        const exists = await users.findOne({ email });
        if (exists) return res.status(400).send({ message: 'Email already exists' });

        const passwordHash = await bcrypt.hash(password, 10);
        await users.insertOne({
            name, email, passwordHash,
            devices: [], createdAt: new Date(), isAdmin: false
        });
        
        res.send({ success: true, message: 'User registered' });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

authRouter.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await req.db.collection('users').findOne({ email });
        
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).send({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.send({ success: true, token });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

authRouter.post('/password/forgot', async (req, res) => {
    if (!mailTransporter) return res.status(503).send({ message: 'Email service unavailable' });
    
    try {
        const { email } = req.body;
        const user = await req.db.collection('users').findOne({ email });
        
        // নিরাপত্তা: ইউজার না থাকলেও আমরা বলব ইমেইল পাঠানো হয়েছে
        if (user) {
            const tempPass = crypto.randomBytes(4).toString('hex');
            const hash = await bcrypt.hash(tempPass, 10);
            
            await req.db.collection('users').updateOne({ _id: user._id }, { $set: { passwordHash: hash } });
            
            await mailTransporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset',
                text: `Your new temporary password is: ${tempPass}\nPlease change it immediately.`
            });
        }
        res.send({ success: true, message: 'If account exists, email sent.' });
    } catch (e) { res.status(500).send({ error: e.message }); }
});


// ৪. ইউজার প্রোটেক্টেড রাউটস
const userRouter = express.Router();
userRouter.use(authenticateJWT);

userRouter.get('/profile', async (req, res) => {
    try {
        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) }, { projection: { passwordHash: 0 } });
        if (user) {
            user.isAdmin = user.isAdmin || (process.env.ADMIN_EMAIL === user.email);
            res.send(user);
        } else {
            res.status(404).send({ message: "User not found." });
        }
    } catch(e) {
        res.status(500).send({ message: 'Internal server error fetching profile.'});
    }
});

userRouter.post('/profile/update', async (req, res) => {
    try {
        const { name, address, mobile } = req.body;
        const updateFields = {};
        if (name) updateFields.name = name;
        if (address) updateFields.address = address;
        if (mobile) updateFields.mobile = mobile;

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).send({ message: "No fields to update." });
        }
        
        await req.db.collection('users').updateOne({ _id: new ObjectId(req.user.userId) }, { $set: updateFields });
        res.send({ success: true, message: "Profile updated." });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});


userRouter.get('/devices', async (req, res) => {
    const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
    if (!user || !user.devices) return res.send([]);

    const devices = await req.db.collection('devices').find({ uid: { $in: user.devices } }).toArray();
    res.send(devices);
});

userRouter.post('/device/add', async (req, res) => {
    const { uid } = req.body;
    if(!uid) return res.status(400).send({message: 'UID needed'});
    
    await req.db.collection('users').updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $addToSet: { devices: String(uid).trim() } }
    );
    res.send({ success: true, message: 'Device Added' });
});

userRouter.post('/backup/start', async (req, res) => {
    const { uid } = req.body;
    if (!uid) return res.status(400).send({ message: 'UID required' });
    
    const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
    if (!user || !user.devices || !user.devices.includes(String(uid))) {
        if (!user.isAdmin && process.env.ADMIN_EMAIL !== user.email) {
            return res.status(403).send({ message: 'Not authorized for this device' });
        }
    }

    const q = { uid: String(uid) };
    const jobId = randomUUID();
    const tmpDir = path.join(os.tmpdir(), `esp-backup-${jobId}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    
    const job = { status: 'pending', progress: 0, tmpDir, zipPath: path.join(tmpDir, 'espdata.zip') };
    backupJobs.set(jobId, job);

    res.send({ jobId });

    (async () => {
        try {
            job.status = 'exporting';
            const total = await req.db.collection('espdata2').countDocuments(q);
            const out = fs.createWriteStream(path.join(tmpDir, 'espdata.json'), { encoding: 'utf8' });
            out.write('[');
            let first = true, written = 0;
            for await (const doc of req.db.collection('espdata2').find(q).sort({ receivedAt: 1 })) {
                if (!first) out.write(',');
                const clean = { 
                    uid: doc.uid, timestamp: doc.timestamp, dateTime: doc.dateTime,
                    pssensor: doc.pssensor, environment: doc.environment, rain: doc.rain,
                    receivedAt: doc.receivedAt
                };
                out.write(JSON.stringify(clean));
                first = false; written++;
                if (total > 0) job.progress = Math.floor((written / total) * 90);
            }
            out.write(']'); out.end();
            await new Promise(r => out.on('finish', r));

            job.status = 'zipping';
            const output = fs.createWriteStream(job.zipPath);
            const archive = archiver('zip', { zlib: { level: 9 } });
            archive.pipe(output);
            archive.file(path.join(tmpDir, 'espdata.json'), { name: 'espdata.json' });
            await archive.finalize();
            await new Promise(r => output.on('close', r));

            job.status = 'done'; job.progress = 100; job.finishedAt = new Date();
            job.downloadUrl = `/api/user/backup/download/${jobId}`;

        } catch (err) { job.status = 'error'; job.error = err.message; job.finishedAt = new Date(); }
    })();
});

userRouter.get('/backup/status/:jobId', (req, res) => {
    const jobId = req.params.jobId;
    const token = req.query.token;

    if (!token) return res.status(401).send({ message: 'Token missing' });
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send({ message: 'Invalid token' });

        const job = backupJobs.get(jobId);
        if(!job) return res.status(404).send({message: 'Not found'});
        
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');

        const sendEvent = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

        sendEvent({ status: job.status, progress: job.progress, error: job.error });

        if (job.status === 'done' || job.status === 'error') {
            if (job.status === 'done') sendEvent({ status: 'done', progress: 100, download: job.downloadUrl });
            return res.end();
        }

        const iv = setInterval(() => {
            const currentJob = backupJobs.get(jobId);
            if (!currentJob) {
                clearInterval(iv);
                return res.end();
            }
            sendEvent({ status: currentJob.status, progress: currentJob.progress, error: currentJob.error });
            if (currentJob.status === 'done' || currentJob.status === 'error') {
                if (currentJob.status === 'done') sendEvent({ status: 'done', progress: 100, download: currentJob.downloadUrl });
                clearInterval(iv);
                res.end();
            }
        }, 1000);

        req.on('close', () => clearInterval(iv));
    });
});

userRouter.get('/backup/download/:jobId', (req, res) => {
    const job = backupJobs.get(req.params.jobId);
    if (!job || job.status !== 'done') return res.status(400).send('Not ready or invalid job ID');
    res.download(job.zipPath, 'espdata.zip');
});

userRouter.get('/export/json/:uid', async (req, res) => {
    const { uid } = req.params;
    
    try {
        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        if (!user || !user.devices || !user.devices.includes(String(uid))) {
            if (!user.isAdmin && process.env.ADMIN_EMAIL !== user.email) {
                return res.status(403).send({ message: 'Not authorized for this device' });
            }
        }

        res.setHeader('Content-disposition', `attachment; filename=export_${uid}.json`);
        res.setHeader('Content-type', 'application/json');

        const cursor = req.db.collection('espdata2').find({ uid: String(uid) }).sort({ receivedAt: 1 });
        
        res.write('[');
        let first = true;
        for await (const doc of cursor) {
            if (!first) res.write(',');
            delete doc._id; // Remove _id if it's there
            res.write(JSON.stringify(doc));
            first = false;
        }
        res.write(']');
        res.end();
    } catch (error) {
        console.error('Error in /export/json/:uid:', error);
        if (!res.headersSent) {
            res.status(500).send({ success: false, message: 'Server error during export' });
        } else {
            res.end();
        }
    }
});

userRouter.post('/password/change', async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) return res.status(400).send({ message: "Old and new passwords are required." });

        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        if (!user) return res.status(404).send({ message: "User not found." });

        const isMatch = await bcrypt.compare(oldPassword, user.passwordHash);
        if (!isMatch) return res.status(401).send({ message: "Invalid old password." });
        
        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await req.db.collection('users').updateOne({ _id: user._id }, { $set: { passwordHash: newPasswordHash } });

        res.send({ success: true, message: 'Password changed successfully.' });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

// --- TRASH ROUTES ---
userRouter.get('/trash', async (req, res) => {
    try {
        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        const isAdmin = user && (user.isAdmin || process.env.ADMIN_EMAIL === user.email);
        
        const query = isAdmin ? {} : { deletedBy: req.user.userId };
        const items = await req.db.collection('trash').find(query).sort({ deletedAt: -1 }).toArray();
        res.send(items);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

userRouter.post('/trash/restore/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid ID' });

        const trashItem = await req.db.collection('trash').findOne({ _id: new ObjectId(id) });
        if (!trashItem) return res.status(404).send({ message: 'Item not found in trash' });

        if (trashItem.type === 'telemetry') {
            await req.db.collection('espdata2').insertOne(trashItem.document);
        } else if (trashItem.type === 'device') {
            // Restore device
            const exists = await req.db.collection('devices').findOne({ uid: trashItem.document.uid });
            if (!exists) {
                await req.db.collection('devices').insertOne(trashItem.document);
            }
            // Restore ownership
            if (trashItem.owners && trashItem.owners.length > 0) {
                const ownerIds = trashItem.owners.map(oid => new ObjectId(oid));
                await req.db.collection('users').updateMany(
                    { _id: { $in: ownerIds } },
                    { $addToSet: { devices: trashItem.document.uid } }
                );
            }
        }

        await req.db.collection('trash').deleteOne({ _id: new ObjectId(id) });
        res.send({ success: true, message: 'Restored successfully' });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

userRouter.delete('/trash/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid ID' });

        const result = await req.db.collection('trash').deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) return res.status(404).send({ message: 'Not found' });
        
        res.send({ success: true, message: 'Permanently deleted' });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

userRouter.delete('/device/:uid', async (req, res) => {
    try {
        const { uid } = req.params;
        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        const isAdmin = user && (user.isAdmin || process.env.ADMIN_EMAIL === user.email);

        if (!isAdmin && (!user.devices || !user.devices.includes(uid))) {
            return res.status(403).send({ message: 'Not authorized to delete this device' });
        }

        const device = await req.db.collection('devices').findOne({ uid: String(uid) });
        if (!device) return res.status(404).send({ message: 'Device not found' });

        // Find all users who own this device to restore later
        const owners = await req.db.collection('users').find({ devices: String(uid) }).toArray();
        const ownerIds = owners.map(o => o._id);

        // Move to trash
        await req.db.collection('trash').insertOne({
            type: 'device',
            originalId: device._id,
            document: device,
            owners: ownerIds,
            deletedBy: req.user.userId,
            deletedAt: new Date()
        });

        // Delete from devices collection
        await req.db.collection('devices').deleteOne({ uid: String(uid) });

        // Remove from all users' devices arrays
        await req.db.collection('users').updateMany(
            { devices: String(uid) },
            { $pull: { devices: String(uid) } }
        );

        res.send({ success: true, message: 'Device moved to trash' });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

// ৫. অ্যাডমিন রাউটস
const adminRouter = express.Router();
adminRouter.use(authenticateJWT, ensureAdmin);

adminRouter.get('/stats', async (req, res) => {
    const stats = {
        totalDevices: await req.db.collection('devices').countDocuments(),
        onlineDevices: await req.db.collection('devices').countDocuments({ status: 'online' }),
        totalUsers: await req.db.collection('users').countDocuments(),
    };
    res.send(stats);
});

adminRouter.get('/devices', async (req, res) => {
    try {
        const devices = await req.db.collection('devices').find({}).toArray();
        const allDeviceUIDs = devices.map(d => d.uid);

        const users = await req.db.collection('users').find(
            { devices: { $in: allDeviceUIDs } },
            { projection: { _id: 1, name: 1, email: 1, devices: 1 } }
        ).toArray();

        const userMap = new Map();
        users.forEach(user => {
            user.devices.forEach(uid => {
                if (!userMap.has(uid)) userMap.set(uid, []);
                userMap.get(uid).push({ _id: user._id, name: user.name, email: user.email });
            });
        });

        const result = devices.map(device => ({
            ...device,
            owners: userMap.get(device.uid) || []
        }));

        res.send(result);
    } catch (error) {
        res.status(500).send({ success: false, message: 'Internal server error' });
    }
});


// ডিভাইস আপডেট করার জন্য নতুন রাউট
adminRouter.put('/device/:uid', async (req, res) => {
    try {
        const { uid } = req.params;
        const { location, name, latitude, longitude, institution, water_level } = req.body;
        
        const updateFields = {};
        if (location !== undefined) updateFields.location = location;
        if (name !== undefined) updateFields.name = name;
        if (latitude !== undefined) updateFields.latitude = latitude === null || latitude === '' ? null : parseFloat(latitude);
        if (longitude !== undefined) updateFields.longitude = longitude === null || longitude === '' ? null : parseFloat(longitude);
        if (institution !== undefined) updateFields.institution = institution;
        if (water_level !== undefined) updateFields.water_level = parseFloat(water_level);

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).send({ success: false, message: 'No fields to update.' });
        }

        const result = await req.db.collection('devices').updateOne(
            { uid: uid },
            { $set: updateFields }
        );

        if (result.matchedCount === 0) {
            return res.status(404).send({ success: false, message: 'Device not found.' });
        }
        
        if (result.modifiedCount === 0 && result.matchedCount === 1) {
             return res.send({ success: true, message: 'No changes detected.' });
        }

        res.send({ success: true, message: `Device ${uid} updated successfully.` });
    } catch (error) {
        console.error('Error in /api/admin/device/:uid (PUT):', error);
        res.status(500).send({ success: false, message: 'Internal server error' });
    }
});

// Device Replace / MAC Update Route
adminRouter.put('/device/replace/:oldUid', async (req, res) => {
    try {
        const { oldUid } = req.params;
        const { newUid } = req.body;
        
        if (!newUid || typeof newUid !== 'string') {
            return res.status(400).send({ success: false, message: 'newUid is required and must be a string' });
        }
        
        if (oldUid === newUid) {
            return res.status(400).send({ success: false, message: 'oldUid and newUid must be different' });
        }

        // Check if old device exists
        const oldDevice = await req.db.collection('devices').findOne({ uid: oldUid });
        if (!oldDevice) {
            return res.status(404).send({ success: false, message: 'Old device not found' });
        }

        // Check if new device already exists to avoid conflict
        const newDeviceExists = await req.db.collection('devices').findOne({ uid: newUid });
        if (newDeviceExists) {
            return res.status(400).send({ success: false, message: 'New device UID already exists in database' });
        }

        // 1. Update espdata2 collection
        await req.db.collection('espdata2').updateMany(
            { uid: oldUid },
            { $set: { uid: newUid } }
        );

        // 2. Update devices collection
        await req.db.collection('devices').updateOne(
            { uid: oldUid },
            { $set: { uid: newUid } }
        );

        // 3. Update users collection (replace oldUid with newUid in devices array)
        // Find all users who have the oldUid in their devices array
        const usersToUpdate = await req.db.collection('users').find({ devices: oldUid }).toArray();
        for (const user of usersToUpdate) {
            await req.db.collection('users').updateOne(
                { _id: user._id },
                { 
                    $pull: { devices: oldUid } 
                }
            );
            await req.db.collection('users').updateOne(
                { _id: user._id },
                { 
                    $addToSet: { devices: newUid } 
                }
            );
        }

        res.send({ success: true, message: `Device ${oldUid} successfully replaced with ${newUid}` });
    } catch (error) {
        console.error('Error in /api/admin/device/replace/:oldUid:', error);
        res.status(500).send({ success: false, message: 'Internal server error during device replacement' });
    }
});

// Device Clone Route (Copy data without deleting old, create new device if needed)
adminRouter.post('/device/clone', async (req, res) => {
    try {
        const { sourceUid, targetUid } = req.body;
        
        if (!sourceUid || !targetUid || typeof sourceUid !== 'string' || typeof targetUid !== 'string') {
            return res.status(400).send({ success: false, message: 'sourceUid and targetUid are required and must be strings' });
        }
        
        if (sourceUid === targetUid) {
            return res.status(400).send({ success: false, message: 'sourceUid and targetUid must be different' });
        }

        // Fetch source data
        const sourceData = await req.db.collection('espdata2').find({ uid: sourceUid }).toArray();
        if (sourceData.length === 0) {
            return res.status(404).send({ success: false, message: 'No data found for source UID' });
        }

        // Clone data, modifying UID and removing original _id
        const clonedData = sourceData.map(doc => {
            const { _id, ...rest } = doc;
            return { ...rest, uid: targetUid };
        });

        // Insert cloned data
        await req.db.collection('espdata2').insertMany(clonedData, { ordered: false });

        // Ensure target device exists in devices collection
        const targetDeviceExists = await req.db.collection('devices').findOne({ uid: targetUid });
        if (!targetDeviceExists) {
            const sourceDevice = await req.db.collection('devices').findOne({ uid: sourceUid });
            const newDevice = {
                uid: targetUid,
                status: 'offline',
                addedAt: new Date(),
                name: `Device-${targetUid}`
            };
            if (sourceDevice) {
                if (sourceDevice.location) newDevice.location = sourceDevice.location;
                if (sourceDevice.institution) newDevice.institution = sourceDevice.institution;
            }
            await req.db.collection('devices').insertOne(newDevice);
        }

        // Update users who have sourceUid to also have targetUid
        const usersToUpdate = await req.db.collection('users').find({ devices: sourceUid }).toArray();
        for (const user of usersToUpdate) {
            await req.db.collection('users').updateOne(
                { _id: user._id },
                { $addToSet: { devices: targetUid } }
            );
        }

        res.send({ success: true, message: `Successfully cloned ${sourceData.length} records from ${sourceUid} to ${targetUid}.` });
    } catch (error) {
        console.error('Error in /api/admin/device/clone:', error);
        res.status(500).send({ success: false, message: 'Internal server error during device cloning' });
    }
});



adminRouter.post('/device/generate-history', async (req, res) => {
    try {
        const { uid, months = 18, intervalMins = 15 } = req.body;
        
        if (!uid) {
            return res.status(400).send({ success: false, message: 'Device UID is required' });
        }

        const device = await req.db.collection('devices').findOne({ uid: String(uid) });
        if (!device) {
            return res.status(404).send({ success: false, message: 'Device not found' });
        }

        const endDate = new Date();
        const startDate = new Date();
        startDate.setMonth(startDate.getMonth() - parseInt(months));
        
        let currentDate = new Date(startDate);
        const recordsToInsert = [];
        const intervalMs = parseInt(intervalMins) * 60 * 1000;

        while (currentDate <= endDate) {
            // Randomly fluctuate water level between 2 and 5 (or slightly around base)
            const randomWaterLevel = Math.round((Math.random() * (5 - 2) + 2) * 100) / 100;
            const randomTemp = 20 + Math.random() * 15;
            const randomHum = 50 + Math.random() * 40;
            const randomRain = Math.random() > 0.9 ? Math.random() * 5 : 0;

            recordsToInsert.push({
                uid: String(uid),
                timestamp: currentDate.toISOString(),
                dateTime: currentDate.toISOString(),
                receivedAt: new Date(currentDate),
                environment: {
                    temp: Math.round(randomTemp * 10) / 10,
                    hum: Math.round(randomHum * 10) / 10
                },
                pssensor: {
                    depth_ft: randomWaterLevel
                },
                rain: {
                    mm: Math.round(randomRain * 100) / 100
                },
                temperature: Math.round(randomTemp * 10) / 10,
                humidity: Math.round(randomHum * 10) / 10,
                water_level: randomWaterLevel,
                rainfall: Math.round(randomRain * 100) / 100,
                weather_code: 0,
                wind_speed: Math.round(Math.random() * 20 * 10) / 10,
                apparent_temperature: Math.round((randomTemp + 2) * 10) / 10
            });

            currentDate = new Date(currentDate.getTime() + intervalMs);
        }

        if (recordsToInsert.length > 0) {
            const batchSize = 5000;
            for (let i = 0; i < recordsToInsert.length; i += batchSize) {
                const batch = recordsToInsert.slice(i, i + batchSize);
                await req.db.collection('espdata2').insertMany(batch, { ordered: false });
            }
        }

        res.send({ success: true, message: `Successfully generated ${recordsToInsert.length} historical records for device ${uid}.` });
    } catch (error) {
        console.error('Error generating historical data:', error);
        res.status(500).send({ success: false, message: 'Internal server error during history generation' });
    }
});

adminRouter.get('/users', async (req, res) => {
    try {
        const { search } = req.query;
        let query = {};
        if (search && typeof search === 'string' && search.trim()) {
            const regex = { $regex: search.trim(), $options: 'i' };
            query = {
                $or: [
                    { name: regex },
                    { email: regex },
                    { mobile: regex },
                    { address: regex },
                    { devices: regex }
                ]
            };
        }
        const users = await req.db.collection('users')
            .find(query, { projection: { passwordHash: 0 } })
            .sort({ createdAt: -1 })
            .toArray();
        res.send(users);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

// Admin: Create new user
adminRouter.post('/user', async (req, res) => {
    try {
        const { name, email, password, mobile, address, isAdmin, devices } = req.body;
        if (!name || !email || !password) {
            return res.status(400).send({ success: false, message: 'Name, email and password are required' });
        }
        const cleanEmail = String(email).trim().toLowerCase();
        const usersCol = req.db.collection('users');
        const existing = await usersCol.findOne({ email: cleanEmail });
        if (existing) {
            return res.status(400).send({ success: false, message: 'User with this email already exists' });
        }

        let deviceArray = [];
        if (Array.isArray(devices)) {
            deviceArray = devices.map(d => String(d).trim()).filter(Boolean);
        } else if (typeof devices === 'string') {
            deviceArray = devices.split(',').map(d => d.trim()).filter(Boolean);
        }

        const passwordHash = await bcrypt.hash(String(password), 10);
        const newUser = {
            name: String(name).trim(),
            email: cleanEmail,
            passwordHash,
            mobile: mobile ? String(mobile).trim() : '',
            address: address ? String(address).trim() : '',
            isAdmin: Boolean(isAdmin),
            devices: deviceArray,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const result = await usersCol.insertOne(newUser);
        const { passwordHash: _, ...createdUser } = newUser;
        createdUser._id = result.insertedId;

        res.status(201).send({ success: true, message: 'User created successfully', user: createdUser });
    } catch (e) {
        res.status(500).send({ success: false, error: e.message });
    }
});

// Admin: Update user profile details
adminRouter.put('/user/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, mobile, address, isAdmin, devices, password } = req.body;
        const usersCol = req.db.collection('users');

        let userQuery = null;
        if (ObjectId.isValid(id) && String(new ObjectId(id)) === id) {
            userQuery = { _id: new ObjectId(id) };
        } else {
            userQuery = { email: String(id).trim().toLowerCase() };
        }

        const existingUser = await usersCol.findOne(userQuery);
        if (!existingUser) {
            return res.status(404).send({ success: false, message: 'User not found' });
        }

        const updateFields = { updatedAt: new Date() };

        if (name !== undefined) updateFields.name = String(name).trim();
        if (mobile !== undefined) updateFields.mobile = String(mobile).trim();
        if (address !== undefined) updateFields.address = String(address).trim();
        if (isAdmin !== undefined) updateFields.isAdmin = Boolean(isAdmin);

        if (email !== undefined) {
            const cleanEmail = String(email).trim().toLowerCase();
            if (cleanEmail !== existingUser.email) {
                const duplicate = await usersCol.findOne({ email: cleanEmail, _id: { $ne: existingUser._id } });
                if (duplicate) {
                    return res.status(400).send({ success: false, message: 'Email already in use by another user' });
                }
                updateFields.email = cleanEmail;
            }
        }

        if (devices !== undefined) {
            if (Array.isArray(devices)) {
                updateFields.devices = devices.map(d => String(d).trim()).filter(Boolean);
            } else if (typeof devices === 'string') {
                updateFields.devices = devices.split(',').map(d => d.trim()).filter(Boolean);
            }
        }

        if (password && typeof password === 'string' && password.trim().length > 0) {
            updateFields.passwordHash = await bcrypt.hash(password.trim(), 10);
        }

        await usersCol.updateOne({ _id: existingUser._id }, { $set: updateFields });

        const updatedDoc = await usersCol.findOne({ _id: existingUser._id }, { projection: { passwordHash: 0 } });
        res.send({ success: true, message: 'User profile updated successfully', user: updatedDoc });
    } catch (e) {
        res.status(500).send({ success: false, error: e.message });
    }
});

// Admin: Delete user
adminRouter.delete('/user/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const usersCol = req.db.collection('users');

        let userQuery = null;
        if (ObjectId.isValid(id) && String(new ObjectId(id)) === id) {
            userQuery = { _id: new ObjectId(id) };
        } else {
            userQuery = { email: String(id).trim().toLowerCase() };
        }

        const targetUser = await usersCol.findOne(userQuery);
        if (!targetUser) {
            return res.status(404).send({ success: false, message: 'User not found' });
        }

        // Prevent deleting super admin or oneself
        if (process.env.ADMIN_EMAIL && targetUser.email === process.env.ADMIN_EMAIL) {
            return res.status(403).send({ success: false, message: 'Cannot delete master system administrator' });
        }
        if (req.user && String(targetUser._id) === String(req.user.userId)) {
            return res.status(400).send({ success: false, message: 'Cannot delete your own admin account while logged in' });
        }

        await usersCol.deleteOne({ _id: targetUser._id });
        res.send({ success: true, message: `User ${targetUser.email} deleted successfully` });
    } catch (e) {
        res.status(500).send({ success: false, error: e.message });
    }
});

adminRouter.post('/user/make-admin', async (req, res) => {
    await req.db.collection('users').updateOne({ email: req.body.email }, { $set: { isAdmin: true } });
    res.send({ success: true, message: 'User promoted to Admin' });
});

adminRouter.post('/user/remove-admin', async (req, res) => {
    if (req.body.email === process.env.ADMIN_EMAIL) return res.status(403).send({ message: 'Cannot remove super admin' });
    await req.db.collection('users').updateOne({ email: req.body.email }, { $set: { isAdmin: false } });
    res.send({ success: true, message: 'Admin privileges removed' });
});


adminRouter.get('/report', async (req, res) => {
    const { period = 'monthly', year = new Date().getFullYear().toString() } = req.query;
    let group, sort;
    const matchYear = parseInt(year, 10);

    const matchStage = { 
        receivedAt: { 
            $gte: new Date(matchYear, 0, 1), 
            $lt: new Date(matchYear + 1, 0, 1)
        },
        'environment.temp': { $ne: 85 } // Ignore error value
    };

    switch (period) {
        case 'daily':
            group = {
                _id: { $dateToString: { format: '%Y-%m-%d', date: '$receivedAt', timezone: 'Asia/Dhaka' } },
                avgTemp: { $avg: '$environment.temp' },
                avgRain: { $sum: '$rain.mm' },
                count: { $sum: 1 }
            };
            sort = { '_id': 1 };
            break;
        case 'yearly':
            group = {
                _id: { $year: { date: '$receivedAt', timezone: 'Asia/Dhaka' } },
                avgTemp: { $avg: '$environment.temp' },
                avgRain: { $sum: '$rain.mm' },
                count: { $sum: 1 }
            };
            sort = { '_id': 1 };
            break;
        case 'monthly':
        default:
            group = {
                _id: { $dateToString: { format: '%Y-%m', date: '$receivedAt', timezone: 'Asia/Dhaka' } },
                avgTemp: { $avg: '$environment.temp' },
                avgRain: { $sum: '$rain.mm' },
                count: { $sum: 1 }
            };
            sort = { '_id': 1 };
    }

    try {
        const data = await req.db.collection('espdata2').aggregate([
            { $match: matchStage },
            { $group: group },
            { $sort: sort },
            { $project: {
                _id: 0,
                date: period === 'daily' ? '$_id' : undefined,
                month: period === 'monthly' ? '$_id' : undefined,
                year: period === 'yearly' ? '$_id' : undefined,
                avgTemp: 1,
                avgRain: 1,
                count: 1
            }}
        ]).toArray();
        res.json(data);
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});

adminRouter.post('/backup/start', async (req, res) => {
    const { uid } = req.body;
    const q = uid ? { uid: String(uid).trim() } : {};
    const jobId = randomUUID();
    const tmpDir = path.join(os.tmpdir(), `esp-backup-${jobId}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    
    const job = { status: 'pending', progress: 0, tmpDir, zipPath: path.join(tmpDir, 'espdata.zip') };
    backupJobs.set(jobId, job);

    res.send({ jobId });

    (async () => {
        try {
            job.status = 'exporting';
            const total = uid ? await req.db.collection('espdata2').countDocuments(q) : await req.db.collection('espdata2').estimatedDocumentCount();
            const out = fs.createWriteStream(path.join(tmpDir, 'espdata.json'), { encoding: 'utf8' });
            out.write('[');
            let first = true, written = 0;
            const cursor = req.db.collection('espdata2').find(q).sort({ receivedAt: -1 });
            for await (const doc of cursor) {
                if (!first) out.write(',');
                // Clean Output
                const clean = { 
                    uid: doc.uid, timestamp: doc.timestamp, dateTime: doc.dateTime,
                    pssensor: doc.pssensor, environment: doc.environment, rain: doc.rain,
                    receivedAt: doc.receivedAt
                };
                out.write(JSON.stringify(clean));
                first = false; written++;
                if (total > 0 && written % 100 === 0) {
                    job.progress = Math.min(90, Math.floor((written / total) * 90));
                }
            }
            out.write(']'); out.end();
            await new Promise(r => out.on('finish', r));

            job.status = 'zipping';
            job.progress = 92;
            const output = fs.createWriteStream(job.zipPath);
            const archive = archiver('zip', { zlib: { level: 6 } });
            archive.pipe(output);
            archive.file(path.join(tmpDir, 'espdata.json'), { name: 'espdata.json' });
            await archive.finalize();
            await new Promise(r => output.on('close', r));

            const downloadPath = `/api/admin/backup/download/${jobId}`;
            job.downloadUrl = downloadPath;
            job.status = 'done';
            job.progress = 100;
            job.finishedAt = new Date();

        } catch (err) { job.status = 'error'; job.error = err.message; job.finishedAt = new Date(); }
    })();
});

adminRouter.get('/backup/status/:jobId', (req, res) => {
    const jobId = req.params.jobId;
    const job = backupJobs.get(jobId);
    if (!job) return res.status(404).send({ message: 'Not found' });
    
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

    sendEvent({ status: job.status, progress: job.progress, error: job.error, download: job.downloadUrl });

    if (job.status === 'done' || job.status === 'error') {
        return res.end();
    }

    const iv = setInterval(() => {
        const currentJob = backupJobs.get(jobId);
        if (!currentJob) {
            clearInterval(iv);
            return res.end();
        }
        
        sendEvent({ status: currentJob.status, progress: currentJob.progress, error: currentJob.error, download: currentJob.downloadUrl });
        
        if (currentJob.status === 'done' || currentJob.status === 'error') {
            clearInterval(iv);
            res.end();
        }
    }, 1000);

    req.on('close', () => clearInterval(iv));
});

adminRouter.get('/backup/download/:jobId', (req, res) => {
    const job = backupJobs.get(req.params.jobId);
    if (!job || job.status !== 'done') return res.status(400).send('Not ready or invalid job ID');
    res.download(job.zipPath, 'espdata.zip');
});

adminRouter.get('/ai-chats', async (req, res) => {
    try {
        const { uid, email, role, q, startDate, endDate, limit = 50, page = 1 } = req.query;
        const query = {};

        if (uid && typeof uid === 'string' && uid.trim()) {
            query.uid = uid.trim();
        }
        if (email && typeof email === 'string' && email.trim()) {
            query.userEmail = { $regex: email.trim(), $options: 'i' };
        }
        if (role && (role === 'user' || role === 'assistant')) {
            query.role = role;
        }
        if (q && typeof q === 'string' && q.trim()) {
            query.message = { $regex: q.trim(), $options: 'i' };
        }

        // Date range filter
        const dateFilter = {};
        if (startDate && typeof startDate === 'string' && startDate.trim()) {
            const start = new Date(startDate.trim());
            if (!isNaN(start.getTime())) {
                dateFilter.$gte = start;
            }
        }
        if (endDate && typeof endDate === 'string' && endDate.trim()) {
            const end = new Date(endDate.trim());
            if (!isNaN(end.getTime())) {
                // If date string without time, include full end of day
                if (!endDate.includes('T') && !endDate.includes(':')) {
                    end.setHours(23, 59, 59, 999);
                }
                dateFilter.$lte = end;
            }
        }
        if (Object.keys(dateFilter).length > 0) {
            query.timestamp = dateFilter;
        }

        const pageSize = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 500);
        const pageNum = Math.max(parseInt(page, 10) || 1, 1);
        const skip = (pageNum - 1) * pageSize;

        const chatsCol = req.db.collection('device_chats');
        const [total, totalAll, uniqueUsers, uniqueDevices, chats] = await Promise.all([
            chatsCol.countDocuments(query),
            chatsCol.estimatedDocumentCount().catch(() => 0),
            chatsCol.distinct('userEmail').catch(() => []),
            chatsCol.distinct('uid').catch(() => []),
            chatsCol.find(query)
                .sort({ timestamp: -1 })
                .skip(skip)
                .limit(pageSize)
                .toArray()
        ]);

        res.send({
            success: true,
            page: pageNum,
            limit: pageSize,
            count: chats.length,
            total,
            totalAll,
            uniqueUsersCount: uniqueUsers.filter(Boolean).length,
            uniqueDevicesCount: uniqueDevices.filter(Boolean).length,
            uniqueUsers: uniqueUsers.filter(Boolean),
            uniqueDevices: uniqueDevices.filter(Boolean),
            chats
        });
    } catch (err) {
        res.status(500).send({ success: false, error: err.message });
    }
});

// Admin: Delete a single AI chat message
adminRouter.delete('/ai-chat/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).send({ success: false, message: 'Invalid Chat ID' });
        }
        const result = await req.db.collection('device_chats').deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).send({ success: false, message: 'Chat entry not found' });
        }
        res.send({ success: true, message: 'Chat log deleted successfully' });
    } catch (err) {
        res.status(500).send({ success: false, error: err.message });
    }
});

// Admin: Clear AI chats by device or user
adminRouter.delete('/ai-chats/clear', async (req, res) => {
    try {
        const { uid, email } = req.body;
        const query = {};
        if (uid) query.uid = String(uid).trim();
        if (email) query.userEmail = String(email).trim().toLowerCase();

        if (Object.keys(query).length === 0) {
            return res.status(400).send({ success: false, message: 'Please specify uid or email to clear chats' });
        }

        const result = await req.db.collection('device_chats').deleteMany(query);
        res.send({ success: true, message: `Cleared ${result.deletedCount} chat entries` });
    } catch (err) {
        res.status(500).send({ success: false, error: err.message });
    }
});

// --- Gemini AI Assistant Integration ---
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

async function callGeminiAPI(systemInstruction, messages) {
    if (!GEMINI_API_KEY) {
        throw new Error('GEMINI_API_KEY is not configured in .env file');
    }
    const models = ['gemini-3-flash-preview', 'gemini-flash-latest', 'gemini-flash-lite-latest'];
    let lastError = null;

    const contents = [];
    if (messages && messages.length > 0) {
        messages.forEach(m => {
            contents.push({
                role: m.role === 'assistant' ? 'model' : 'user',
                parts: [{ text: String(m.message || m.text || '') }]
            });
        });
    }

    for (const model of models) {
        try {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;
            const reqBody = {
                system_instruction: {
                    parts: [{ text: systemInstruction }]
                },
                contents: contents,
                generationConfig: {
                    temperature: 0.7,
                    maxOutputTokens: 2048
                }
            };

            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reqBody)
            });

            const data = await response.json();
            if (response.ok && data?.candidates?.[0]?.content?.parts?.[0]?.text) {
                return data.candidates[0].content.parts[0].text;
            }

            if (!response.ok && data?.error?.message?.includes('system_instruction')) {
                const fallbackContents = [
                    { role: 'user', parts: [{ text: `[System Instruction]\n${systemInstruction}\n\n[Conversation]\n` + contents.map(c => `${c.role}: ${c.parts[0].text}`).join('\n') }] }
                ];
                const res2 = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ contents: fallbackContents })
                });
                const d2 = await res2.json();
                if (res2.ok && d2?.candidates?.[0]?.content?.parts?.[0]?.text) {
                    return d2.candidates[0].content.parts[0].text;
                }
            }

            lastError = data?.error?.message || `Model ${model} returned status ${response.status}`;
            console.warn(`[Gemini] ${model} attempt failed:`, lastError);
        } catch (err) {
            lastError = err.message;
            console.warn(`[Gemini] Error calling ${model}:`, err.message);
        }
    }

    throw new Error(lastError || 'Gemini AI service unavailable');
}

// --- AI Chat Router ---
const aiRouter = express.Router();

aiRouter.post('/ai-chat', authenticateJWT, async (req, res) => {
    try {
        const { uid, message } = req.body || {};
        if (!uid || !message || typeof message !== 'string' || !message.trim()) {
            return res.status(400).send({ success: false, message: 'uid and message are required' });
        }

        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        const userName = user?.name || req.user.email || 'User';
        const userEmail = req.user.email;

        // 1. Fetch Device Info
        const device = await req.db.collection('devices').findOne({ uid: String(uid) });

        // 2. Fetch Latest & Recent Sensor Readings from espdata2
        const recentReadings = await req.db.collection('espdata2')
            .find({ uid: String(uid) })
            .sort({ receivedAt: -1 })
            .limit(20)
            .toArray();

        let latestTemp = 'N/A', latestHum = 'N/A', latestWater = 'N/A', latestRain = '0', latestTime = 'N/A';
        let minTemp = null, maxTemp = null, avgTemp = null;
        let minHum = null, maxHum = null, avgHum = null;
        let minWater = null, maxWater = null, avgWater = null;
        let totalRain = 0;
        let waterTrend = 'Stable';
        let humTrend = 'Stable';

        if (recentReadings.length > 0) {
            const first = recentReadings[0];
            const t = first.environment?.temp ?? first.temperature;
            const h = first.environment?.hum ?? first.humidity;
            const w = first.pssensor?.depth_ft ?? first.water_level;
            const r = first.rain?.mm ?? first.rainfall;
            
            latestTemp = (typeof t === 'number' && t !== 85) ? t.toFixed(1) : 'N/A';
            latestHum = (typeof h === 'number' && h <= 100) ? h.toFixed(1) : 'N/A';
            latestWater = (typeof w === 'number') ? w.toFixed(2) : '0';
            latestRain = (typeof r === 'number') ? r.toFixed(2) : '0';
            latestTime = first.receivedAt ? new Date(first.receivedAt).toLocaleString('en-GB') : (first.timestamp || 'N/A');

            const validTemps = recentReadings.map(d => d.environment?.temp ?? d.temperature).filter(v => typeof v === 'number' && v !== 85);
            const validHums = recentReadings.map(d => d.environment?.hum ?? d.humidity).filter(v => typeof v === 'number' && v <= 100);
            const validWaters = recentReadings.map(d => d.pssensor?.depth_ft ?? d.water_level).filter(v => typeof v === 'number');
            const validRains = recentReadings.map(d => d.rain?.mm ?? d.rainfall).filter(v => typeof v === 'number');

            if (validTemps.length > 0) {
                minTemp = Math.min(...validTemps).toFixed(1);
                maxTemp = Math.max(...validTemps).toFixed(1);
                avgTemp = (validTemps.reduce((a, b) => a + b, 0) / validTemps.length).toFixed(1);
            }
            if (validHums.length > 0) {
                minHum = Math.min(...validHums).toFixed(1);
                maxHum = Math.max(...validHums).toFixed(1);
                avgHum = (validHums.reduce((a, b) => a + b, 0) / validHums.length).toFixed(1);
            }
            if (validWaters.length > 0) {
                minWater = Math.min(...validWaters).toFixed(2);
                maxWater = Math.max(...validWaters).toFixed(2);
                avgWater = (validWaters.reduce((a, b) => a + b, 0) / validWaters.length).toFixed(2);
                
                const newest = validWaters[0];
                const oldest = validWaters[validWaters.length - 1];
                if (newest - oldest > 0.3) waterTrend = `Rising (+${(newest - oldest).toFixed(2)} ft)`;
                else if (oldest - newest > 0.3) waterTrend = `Falling (-${(oldest - newest).toFixed(2)} ft)`;
                else waterTrend = 'Stable';
            }
            if (validHums.length > 1) {
                const newestH = validHums[0];
                const oldestH = validHums[validHums.length - 1];
                if (newestH - oldestH > 5) humTrend = `Increasing (+${(newestH - oldestH).toFixed(1)}%)`;
                else if (oldestH - newestH > 5) humTrend = `Decreasing (-${(oldestH - newestH).toFixed(1)}%)`;
                else humTrend = 'Steady';
            }
            totalRain = validRains.reduce((a, b) => a + b, 0).toFixed(2);
        }

        const recentPointsSummary = recentReadings.slice(0, 8).map(d => {
            const time = d.receivedAt ? new Date(d.receivedAt).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) : '';
            const t = d.environment?.temp ?? d.temperature;
            const h = d.environment?.hum ?? d.humidity;
            const w = d.pssensor?.depth_ft ?? d.water_level;
            const r = d.rain?.mm ?? d.rainfall;
            return `[${time}] Temp: ${t ?? '-'}°C, Hum: ${h ?? '-'}%, Water: ${w ?? '-'}ft, Rain: ${r ?? '-'}mm`;
        }).join('\n');

        const systemInstruction = `You are EMS AI Assistant (পরিবেশ ও আবহাওয়া পর্যবেক্ষণ সহকারী), an intelligent real-time IoT Environmental Monitoring and Weather Forecasting AI for the Environmental Monitoring Network.
You are actively monitoring the IoT Device UID: "${uid}".

### Device Metadata:
- Upazila/Device Name: ${device?.name || 'Unnamed Device'}
- Location: ${device?.location || 'Unknown Location'}
- Institution: ${device?.institution || 'Institution N/A'}
- Coordinates: Latitude ${device?.latitude || 'N/A'}, Longitude ${device?.longitude || 'N/A'}
- Connection Status: ${device?.status || 'unknown'} (Last seen: ${device?.lastSeen ? new Date(device.lastSeen).toLocaleString('en-GB') : 'Unknown'})

### Current Sensor Readings:
- Temperature: ${latestTemp} °C
- Humidity: ${latestHum} %
- Water Level: ${latestWater} ft
- Rainfall: ${latestRain} mm
- Timestamp of latest record: ${latestTime}

### Recent Statistical Range:
- Temperature: Min ${minTemp ?? 'N/A'}°C, Max ${maxTemp ?? 'N/A'}°C, Avg ${avgTemp ?? 'N/A'}°C
- Humidity: Min ${minHum ?? 'N/A'}%, Max ${maxHum ?? 'N/A'}%, Avg ${avgHum ?? 'N/A'}%
- Water Level: Min ${minWater ?? 'N/A'}ft, Max ${maxWater ?? 'N/A'}ft, Avg ${avgWater ?? 'N/A'}ft
- Water Level Trend: ${waterTrend}
- Humidity Trend: ${humTrend}
- Accumulated Rain in recent period: ${totalRain} mm

### Recent Data Points:
${recentPointsSummary || 'No recent data points recorded.'}

### User Asking:
- Name: ${userName}
- Email: ${userEmail}

### Core Directives:
1. **Device Insights**: Explain any sensor reading clearly. Help the user understand what these values mean for human comfort, agriculture, flood safety, and local environment.
2. **Future Weather & Hazard Prediction**:
   - Provide localized weather forecast and environmental prediction based on the device's sensor trends (temperature changes, humidity saturation near 85-100%, atmospheric patterns, water level shifts) and geographic location in Bangladesh.
   - If water level is rising or high along with high rainfall/humidity, warn about flood or waterlogging danger.
   - If humidity is very high and temperature is dropping, predict impending rain.
   - If humidity is moderate/low with steady temperature, predict dry and clear conditions.
3. **Language**: Always reply in the same language the user asks in (Bengali বাংলা, English, or Banglish). Be respectful, professional, and clear.
4. **Formatting**: Use neat Markdown (bold key stats, bullet points, headers, emojis 🌡️ 💧 🌊 🌧️ ☀️ ⚠️).`;

        // Previous 6 messages for continuous dialogue context
        const chatHistory = await req.db.collection('device_chats')
            .find({ uid: String(uid), userId: req.user.userId })
            .sort({ timestamp: -1 })
            .limit(6)
            .toArray();
        chatHistory.reverse();

        const messageList = chatHistory.map(c => ({
            role: c.role,
            message: c.message
        }));
        messageList.push({
            role: 'user',
            message: message.trim()
        });

        const aiReply = await callGeminiAPI(systemInstruction, messageList);

        // Save User Message to Database
        const userMsgDoc = {
            uid: String(uid),
            userId: req.user.userId,
            userEmail: userEmail,
            userName: userName,
            role: 'user',
            message: message.trim(),
            timestamp: new Date()
        };
        await req.db.collection('device_chats').insertOne(userMsgDoc);

        // Save AI Reply to Database
        const aiMsgDoc = {
            uid: String(uid),
            userId: req.user.userId,
            userEmail: userEmail,
            userName: 'EMS AI',
            role: 'assistant',
            message: aiReply,
            timestamp: new Date()
        };
        await req.db.collection('device_chats').insertOne(aiMsgDoc);

        return res.send({
            success: true,
            reply: aiReply,
            timestamp: aiMsgDoc.timestamp
        });

    } catch (error) {
        console.error('Error in /api/device/ai-chat:', error);
        return res.status(500).send({
            success: false,
            message: error.message || 'Failed to process AI chat request'
        });
    }
});

aiRouter.get('/ai-chat/history', authenticateJWT, async (req, res) => {
    try {
        const { uid } = req.query;
        if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });

        const history = await req.db.collection('device_chats')
            .find({ uid: String(uid), userId: req.user.userId })
            .sort({ timestamp: 1 })
            .limit(100)
            .toArray();

        return res.send({ success: true, history });
    } catch (error) {
        console.error('Error in /api/device/ai-chat/history:', error);
        return res.status(500).send({ success: false, message: error.message });
    }
});

aiRouter.delete('/ai-chat/history', authenticateJWT, async (req, res) => {
    try {
        const { uid } = req.query;
        if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });

        await req.db.collection('device_chats').deleteMany({
            uid: String(uid),
            userId: req.user.userId
        });

        return res.send({ success: true, message: 'Chat history cleared' });
    } catch (error) {
        console.error('Error in delete /api/device/ai-chat/history:', error);
        return res.status(500).send({ success: false, message: error.message });
    }
});

// --- রাউটার মাউন্টিং ---
app.use('/api', iotRouter);
app.use('/api/public', publicRouter); 
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.use('/api/admin', adminRouter);
app.use('/api/device', aiRouter);
app.use('/api/ai', aiRouter);

// রুট রুট এবং লগইন পেজ
app.get(['/', '/login'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Open-Meteo 15 Minute Auto-Fetch ---
async function fetchOpenMeteoForAllDevices() {
    if (!db) return;
    try {
        const devicesCollection = db.collection('devices');
        const devices = await devicesCollection.find({
            latitude: { $exists: true, $ne: null, $ne: "" },
            longitude: { $exists: true, $ne: null, $ne: "" }
        }).toArray();

        for (const device of devices) {
            const url = `https://weatherapi.espserver.site/v1/forecast?latitude=${device.latitude}&longitude=${device.longitude}&current=temperature_2m,relative_humidity_2m,apparent_temperature,rain,precipitation,weather_code,wind_speed_10m&timezone=auto&models=best_match`;
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    console.error(`[Open-Meteo API Error] Device ${device.uid}: ${response.statusText}`);
                    continue;
                }
                const data = await response.json();
                
                if (data && data.current) {
                    const current = data.current;
                    let rainValue = current.rain !== undefined && current.rain !== null ? current.rain : (current.precipitation || 0);
                    
                    // --- Virtual ESP Rainfall Simulation (Testing) ---
                    // যদি সত্যিকারের বৃষ্টি না থাকে (0 হয়), তবে ড্যাশবোর্ডে ডেটা দেখানোর জন্য রেন্ডম ভ্যালু দিচ্ছি
                    if (rainValue === 0) {
                        // ৫০% সময়ে একটু বৃষ্টি সিমুলেট করবে (০ থেকে ৫ মিমি এর মধ্যে)
                        if (Math.random() < 0.5) {
                            rainValue = Math.round((Math.random() * 5) * 100) / 100;
                        }
                    }
                    // -------------------------------------------------

                    // --- Virtual ESP Water Level Fluctuation ---
                    if (waterLevelOffsets[device.uid] === undefined) {
                        waterLevelOffsets[device.uid] = 0;
                    }
                    let drift = (Math.random() * 1.0) - 0.5;
                    waterLevelOffsets[device.uid] += drift;
                    if (waterLevelOffsets[device.uid] > 3) waterLevelOffsets[device.uid] = 3;
                    if (waterLevelOffsets[device.uid] < -3) waterLevelOffsets[device.uid] = -3;
                    
                    let baseWaterLevel = parseFloat(device.water_level) || 0;
                    let simulatedWaterLevel = Math.max(0, baseWaterLevel + waterLevelOffsets[device.uid]);
                    simulatedWaterLevel = Math.round(simulatedWaterLevel * 100) / 100;
                    // -------------------------------------------

                    const newData = {
                        uid: device.uid,
                        timestamp: new Date().toISOString(),
                        receivedAt: new Date(),
                        environment: {
                            temp: current.temperature_2m,
                            hum: current.relative_humidity_2m
                        },
                        pssensor: {
                            depth_ft: simulatedWaterLevel
                        },
                        rain: {
                            mm: rainValue
                        },
                        weather_code: current.weather_code,
                        wind_speed: current.wind_speed_10m,
                        temperature: current.temperature_2m,
                        humidity: current.relative_humidity_2m,
                        water_level: simulatedWaterLevel,
                        rainfall: rainValue,
                        apparent_temperature: current.apparent_temperature
                    };

                    espDataBuffer.push(newData);
                }
            } catch (err) {
                console.error(`[Open-Meteo Fetch Error] Device: ${device.uid}`, err.message);
            }
        }
    } catch (err) {
        console.error('[Open-Meteo Global Fetch Error]', err.message);
    }
}

// --- 30 Days Authentic Rainfall Sync (Every 12 Hours) ---
async function syncAuthenticRainfallData() {
    if (!db) return;
    try {
        console.log('[Rain Sync] Starting authentic 30 days rainfall sync for all devices...');
        const devicesCollection = db.collection('devices');
        const espCollection = db.collection('espdata2');
        
        const devices = await devicesCollection.find({
            latitude: { $exists: true, $ne: null, $ne: "" },
            longitude: { $exists: true, $ne: null, $ne: "" }
        }).toArray();

        for (const device of devices) {
            const url = `https://weatherapi.espserver.site/v1/forecast?latitude=${device.latitude}&longitude=${device.longitude}&past_days=30&hourly=rain&timezone=auto`;
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    console.error(`[Rain Sync Error] Device ${device.uid}: ${response.statusText}`);
                    continue;
                }
                const data = await response.json();
                
                if (data && data.hourly && data.hourly.time && data.hourly.rain) {
                    const times = data.hourly.time;
                    const rains = data.hourly.rain;
                    
                    const bulkOps = [];
                    
                    for (let i = 0; i < times.length; i++) {
                        const timeStr = times[i];
                        let rainValue = rains[i];
                        if (rainValue === null || rainValue === undefined) continue;
                        
                        const startTime = new Date(timeStr);
                        if (isNaN(startTime.getTime())) continue;
                        
                        const endTime = new Date(startTime.getTime() + 60 * 60 * 1000); // 1 hour window

                        bulkOps.push({
                            updateMany: {
                                filter: {
                                    uid: device.uid,
                                    receivedAt: { $gte: startTime, $lt: endTime }
                                },
                                update: {
                                    $set: {
                                        'rain.mm': rainValue,
                                        'rainfall': rainValue
                                    }
                                }
                            }
                        });
                    }

                    if (bulkOps.length > 0) {
                        const BATCH_SIZE = 100;
                        for (let k = 0; k < bulkOps.length; k += BATCH_SIZE) {
                            const batch = bulkOps.slice(k, k + BATCH_SIZE);
                            await espCollection.bulkWrite(batch, { ordered: false });
                        }
                    }
                    console.log(`[Rain Sync] Device ${device.uid} updated with authentic rainfall.`);
                }
            } catch (err) {
                console.error(`[Rain Sync Fetch Error] Device: ${device.uid}`, err.message);
            }
        }
        console.log('[Rain Sync] Completed authentic rainfall sync.');
    } catch (err) {
        console.error('[Rain Sync Global Error]', err.message);
    }
}

// --- Auto Sync Historical Data (Last 72 hours, Every 24 hours) ---
async function autoSyncHistoricalDataLast72Hours() {
    if (!db) return;
    try {
        console.log('[Auto Historical Sync] Starting 72-hour sync for all devices...');
        const devicesCollection = db.collection('devices');
        const espCollection = db.collection('espdata2');
        
        const devices = await devicesCollection.find({
            latitude: { $exists: true, $ne: null, $ne: "" },
            longitude: { $exists: true, $ne: null, $ne: "" }
        }).toArray();

        for (const device of devices) {
            const lat = device.latitude;
            const lon = device.longitude;
            const uid = device.uid;
            const baseWaterLevel = device.water_level || 0;

            const url = `https://weatherapi.espserver.site/v1/forecast?latitude=${lat}&longitude=${lon}&past_days=3&hourly=temperature_2m,relative_humidity_2m,rain&timezone=auto`;
            
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    console.error(`[Auto Historical Sync Error] Device ${uid}: ${response.statusText}`);
                    continue;
                }
                const data = await response.json();
                
                if (data && data.hourly && data.hourly.time) {
                    const times = data.hourly.time;
                    const temps = data.hourly.temperature_2m;
                    const hums = data.hourly.relative_humidity_2m;
                    const rains = data.hourly.rain;
                    
                    if (times.length === 0) continue;

                    // Delete existing data for the last 3 days to avoid duplicates
                    const startDataDate = new Date(times[0]);
                    const endDataDate = new Date(times[times.length - 1]);
                    
                    await espCollection.deleteMany({
                        uid: String(uid),
                        receivedAt: { $gte: startDataDate, $lte: new Date(endDataDate.getTime() + 86400000) }
                    });

                    const recordsToInsert = [];
                    
                    for (let i = 0; i < times.length; i++) {
                        const timeStr = times[i];
                        const baseDateObj = new Date(timeStr);
                        if (isNaN(baseDateObj.getTime()) || baseDateObj > new Date()) continue; // Skip future dates
                        
                        const temp = temps[i] !== null ? temps[i] : 25.0;
                        const hum = hums[i] !== null ? hums[i] : 60.0;
                        const rain = rains[i] !== null ? rains[i] : 0.0;

                        // Generate 15-minute interval data (4 records per hour)
                        for (let m = 0; m < 4; m++) {
                            const dateObj = new Date(baseDateObj.getTime() + m * 15 * 60000);
                            if (dateObj > new Date()) continue; 

                            const fluctuation = (Math.random() * 1) - 0.5; 
                            let calcWaterLevel = baseWaterLevel + fluctuation;
                            if (rain > 0) calcWaterLevel += (rain * 0.1); 
                            calcWaterLevel = Math.round(calcWaterLevel * 100) / 100;
                            if (calcWaterLevel < 0) calcWaterLevel = 0;

                            const doc = {
                                uid: String(uid),
                                receivedAt: dateObj,
                                timestamp: dateObj.toISOString(),
                                dateTime: dateObj.toISOString(),
                                version: "1.0",
                                environment: { temp: temp, hum: hum },
                                rain: { mm: rain },
                                pssensor: { depth_ft: calcWaterLevel },
                                temperature: temp,
                                humidity: hum,
                                rainfall: rain,
                                water_level: calcWaterLevel
                            };
                            recordsToInsert.push(doc);
                        }
                    }

                    if (recordsToInsert.length > 0) {
                        const batchSize = 100;
                        for (let k = 0; k < recordsToInsert.length; k += batchSize) {
                            const batch = recordsToInsert.slice(k, k + batchSize);
                            await espCollection.insertMany(batch, { ordered: false });
                        }
                    }
                    console.log(`[Auto Historical Sync] Device ${uid} generated ${recordsToInsert.length} records.`);
                }
            } catch (err) {
                console.error(`[Auto Historical Sync Fetch Error] Device: ${uid}`, err.message);
            }
        }
        console.log('[Auto Historical Sync] Completed 72-hour sync for all devices.');
    } catch (err) {
        console.error('[Auto Historical Sync Global Error]', err.message);
    }
}

// --- সার্ভার স্টার্টআপ ফাংশন ---
async function startServer() {
    try {
        if (!MONGODB_URI) throw new Error("MONGODB_URI missing in .env");
        
        const client = new MongoClient(MONGODB_URI, {
            maxPoolSize: 50,
            serverSelectionTimeoutMS: 45000,
            socketTimeoutMS: 60000,
            connectTimeoutMS: 30000,
            waitQueueTimeoutMS: 45000
        });
        await client.connect();
        db = client.db('Esp32data');
        console.log('[Database] MongoDB Connected Successfully');

        // ইনডেক্স তৈরি (একবার রান হবে)
        db.collection('espdata2').createIndex({ receivedAt: -1 }).catch(err => console.warn('[Index espdata2]', err.message));
        db.collection('espdata2').createIndex({ uid: 1 }).catch(err => console.warn('[Index espdata2 uid]', err.message));
        db.collection('users').createIndex({ email: 1 }, { unique: true }).catch(err => console.warn('[Index users]', err.message));
        db.collection('devices').createIndex({ uid: 1 }, { unique: true }).catch(err => console.warn('[Index devices]', err.message));

        // ক্রোন জবস / টাইমার
        setInterval(processDataBuffer, BATCH_INTERVAL_MS);
        setInterval(checkOfflineDevices, OFFLINE_CHECK_INTERVAL_MS);
        setInterval(cleanupBackups, 3600000); // ১ ঘণ্টা পর পর
        setInterval(fetchOpenMeteoForAllDevices, 15 * 60 * 1000); // ১৫ মিনিট পর পর
        setTimeout(fetchOpenMeteoForAllDevices, 15000); // সার্ভার চালুর ১৫ সেকেন্ড পর একবার রান করবে

        // Authentic Rain Sync - Every 12 Hours
        setInterval(syncAuthenticRainfallData, 12 * 60 * 60 * 1000);
        setTimeout(syncAuthenticRainfallData, 60000); // সার্ভার চালুর ১ মিনিট পর রান করবে

        // Auto Historical Sync - Every 24 Hours
        setInterval(autoSyncHistoricalDataLast72Hours, 24 * 60 * 60 * 1000);
        setTimeout(autoSyncHistoricalDataLast72Hours, 120000); // সার্ভার চালুর ২ মিনিট পর রান করবে

        // সার্ভার লিসেন
        http_server.listen(PORT, () => {
            console.log(`[Server] Running on port ${PORT}`);
            console.log(`[Time] Server Time: ${new Date().toString()}`);
        });

    } catch (error) {
        console.error('[Startup Error]', error);
        process.exit(1);
    }
}
 
startServer();

    

    

    





