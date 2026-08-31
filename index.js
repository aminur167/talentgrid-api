const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.disable('x-powered-by');

// Permissive CORS for Vercel production + preview domains + localhost
app.use(cors({
  origin: (origin, callback) => {
    // Allow server-to-server, mobile, curl, or any origin
    callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
  res.setHeader('Connection', 'keep-alive');
  next();
});

// ─── MongoDB & Stripe Setup ───────────────────────────────────────────────────
const uri = process.env.MONGODB_URI;
const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = stripeKey ? require('stripe')(stripeKey) : null;
const JWT_SECRET = process.env.JWT_SECRET || 'hireloop_super_secret_jwt_key_2026_x9k2m';

if (!uri) {
  console.error('❌ MONGODB_URI is not defined in .env');
}

// Cached MongoDB Client for Vercel Serverless
let cachedClient = null;
let cachedDb = null;

async function getDb() {
  if (cachedDb) return cachedDb;
  if (!cachedClient) {
    cachedClient = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    });
    await cachedClient.connect();
  }
  cachedDb = cachedClient.db('hireloop_db');
  return cachedDb;
}

let db, jobsCollection, applicationsCollection, usersCollection, companiesCollection, tokensCollection, subscriptionsCollection, notificationsCollection, savedJobsCollection, interviewsCollection;

async function initCollections() {
  if (!db) {
    db = await getDb();
    jobsCollection          = db.collection('jobs');
    applicationsCollection  = db.collection('applications');
    usersCollection         = db.collection('users');
    companiesCollection     = db.collection('companies');
    tokensCollection        = db.collection('tokens');
    subscriptionsCollection = db.collection('subscriptions');
    notificationsCollection = db.collection('notifications');
    savedJobsCollection     = db.collection('saved_jobs');
    interviewsCollection    = db.collection('interviews');
  }
}

// Helper to safely escape special regex characters from user inputs
function escapeRegex(str) {
  if (!str || typeof str !== 'string') return '';
  return str.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Middleware to ensure DB is connected before handling any route
app.use(async (req, res, next) => {
  try {
    await initCollections();
    next();
  } catch (err) {
    console.error('Database connection error:', err);
    res.status(500).json({ success: false, message: 'Database connection failed' });
  }
});

// ─── JWT Verification Middleware ──────────────────────────────────────────
const verifyToken = async (req, res, next) => {
  try {
    const token =
      req.cookies?.hl_token ||
      (req.headers?.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.split(' ')[1]
        : null);

    if (!token) {
      return res.status(401).json({ success: false, message: 'Authentication required. Please log in.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token. Please log in again.' });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized. Please sign in.' });
  }
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({
      success: false,
      message: `Forbidden: requires ${roles.join(' or ')} permission.`,
    });
  }
  next();
};

// ═══════════════════════════════════════════════════════════════════════════
// AUTH & JWT ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/auth/token — Issue or refresh JWT token in HttpOnly cookie
app.post('/api/auth/token', async (req, res) => {
  try {
    const { email, role, name, id } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    let user = await usersCollection.findOne({ email });
    const userRole = user?.role || role || 'job_seeker';
    const userName = user?.name || name || 'User';
    const userId = user?._id?.toString() || id || '';

    const payload = {
      id: userId,
      email,
      name: userName,
      role: userRole,
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });

    await tokensCollection.insertOne({
      userId,
      email,
      token,
      role: userRole,
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const isProd = process.env.NODE_ENV === 'production';
    res.cookie('hl_token', token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    res.status(200).json({
      success: true,
      message: 'Token issued successfully.',
      user: payload,
      token,
    });
  } catch (error) {
    console.error('POST /api/auth/token error:', error);
    res.status(500).json({ success: false, message: 'Failed to issue auth token.' });
  }
});

// POST /api/auth/logout — Clear JWT cookie
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('hl_token', { path: '/' });
  res.status(200).json({ success: true, message: 'Logged out successfully.' });
});

// GET /api/auth/me — Return current logged-in user from JWT
app.get('/api/auth/me', verifyToken, (req, res) => {
  res.status(200).json({ success: true, user: req.user });
});

// ═══════════════════════════════════════════════════════════════════════════
// JOBS ROUTES — /api/jobs
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/jobs — Create a new job posting
app.post('/api/jobs', async (req, res) => {
  try {
    const job = req.body;

    if (!job.title || !job.category || !job.jobType || !job.deadline) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields: title, category, jobType, deadline',
      });
    }

    const newJob = {
      ...job,
      minSalary: Number(job.minSalary) || 0,
      maxSalary: Number(job.maxSalary) || 0,
      isRemote: job.isRemote === true || job.isRemote === 'true' || String(job.location || '').toLowerCase().includes('remote'),
      status: 'active',
      applications: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await jobsCollection.insertOne(newJob);
    res.status(201).json({
      success: true,
      message: 'Job posted successfully!',
      jobId: result.insertedId,
    });
  } catch (error) {
    console.error('POST /api/jobs error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// GET /api/jobs — Get all jobs (with dynamic typeCounts and filters)
app.get('/api/jobs', async (req, res) => {
  try {
    const { search, category, jobType, isRemote, minSalary, maxSalary, companyId, recruiterEmail, status, location, limit } = req.query;

    const filter = {};

    if (status && status !== 'all') {
      filter.status = status;
    } else if (!status) {
      filter.status = { $ne: 'closed' };
    }

    if (companyId) filter.companyId = companyId;
    if (recruiterEmail) filter.recruiterEmail = recruiterEmail;
    if (search && search.trim()) {
      const safeSearch = escapeRegex(search);
      filter.$or = [
        { title: { $regex: safeSearch, $options: 'i' } },
        { companyName: { $regex: safeSearch, $options: 'i' } },
        { category: { $regex: safeSearch, $options: 'i' } },
        { description: { $regex: safeSearch, $options: 'i' } },
      ];
    }
    if (category && category !== 'All') filter.category = { $regex: escapeRegex(category), $options: 'i' };
    if (jobType && jobType !== 'All') filter.jobType = { $regex: `^${escapeRegex(jobType)}$`, $options: 'i' };

    if (isRemote === 'true' || location === '@remote' || String(location).toLowerCase().includes('remote')) {
      filter.isRemote = true;
    } else if (location && location !== 'all') {
      filter.location = { $regex: escapeRegex(location), $options: 'i' };
    }

    if (minSalary) filter.maxSalary = { $gte: Number(minSalary) };
    if (maxSalary) filter.minSalary = { ...filter.minSalary, $lte: Number(maxSalary) };

    let query = jobsCollection.find(filter).sort({ createdAt: -1 });
    if (limit) query = query.limit(parseInt(limit));

    const jobs = await query.toArray();

    const baseFilter = { ...filter };
    delete baseFilter.jobType;
    const allMatchingJobs = await jobsCollection.find(baseFilter).toArray();

    const typeCounts = {
      'all': allMatchingJobs.length,
      'full-time': 0,
      'part-time': 0,
      'contract': 0,
      'internship': 0,
      'remote': 0,
    };

    for (const j of allMatchingJobs) {
      const t = (j.jobType || '').toLowerCase().trim();
      if (typeCounts[t] !== undefined) {
        typeCounts[t] += 1;
      }
      if (j.isRemote) {
        typeCounts.remote += 1;
      }
    }

    res.status(200).json({
      success: true,
      total: jobs.length,
      jobs,
      typeCounts,
    });
  } catch (error) {
    console.error('GET /api/jobs error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch jobs.' });
  }
});

// GET /api/jobs/:id — Get single job details
app.get('/api/jobs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid job ID.' });
    }
    const job = await jobsCollection.findOne({ _id: new ObjectId(id) });
    if (!job) return res.status(404).json({ success: false, message: 'Job not found.' });
    res.status(200).json({ success: true, job });
  } catch (error) {
    console.error('GET /api/jobs/:id error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// PATCH /api/jobs/:id — Update a job posting
app.patch('/api/jobs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid job ID.' });
    }
    const updates = { ...req.body, updatedAt: new Date() };
    delete updates._id;

    const result = await jobsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: 'Job not found.' });
    }
    res.status(200).json({ success: true, message: 'Job updated successfully.' });
  } catch (error) {
    console.error('PATCH /api/jobs/:id error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// DELETE /api/jobs/:id — Delete a job posting
app.delete('/api/jobs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid job ID.' });
    }
    const result = await jobsCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: 'Job not found.' });
    }
    res.status(200).json({ success: true, message: 'Job deleted successfully.' });
  } catch (error) {
    console.error('DELETE /api/jobs/:id error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// APPLICATIONS ROUTES — /api/applications
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/applications — Apply for a job
app.post('/api/applications', async (req, res) => {
  try {
    const { jobId, applicantEmail, applicantName, coverLetter, resumeUrl, expectedSalary, availability } = req.body;
    if (!jobId || !applicantEmail) {
      return res.status(400).json({
        success: false,
        message: 'jobId and applicantEmail are required.',
      });
    }

    const emailClean = String(applicantEmail).trim().toLowerCase();

    // Check active paid subscription
    const userSubscription = await subscriptionsCollection.findOne({
      userEmail: { $regex: `^${emailClean}$`, $options: 'i' },
      status: 'active',
    });
    const isPro = userSubscription && (userSubscription.plan === 'growth' || userSubscription.plan === 'premium');

    // Count user's current applications
    const userAppCount = await applicationsCollection.countDocuments({
      applicantEmail: { $regex: `^${emailClean}$`, $options: 'i' }
    });

    if (!isPro && userAppCount >= 3) {
      return res.status(403).json({
        success: false,
        code: 'FREE_LIMIT_REACHED',
        message: 'You have used all 3 free job applications. Please upgrade to Growth or Premium to apply for unlimited jobs.',
        redirectUrl: '/plans',
      });
    }

    // Check duplicate application
    const existing = await applicationsCollection.findOne({
      jobId,
      applicantEmail: { $regex: `^${emailClean}$`, $options: 'i' }
    });

    if (existing) {
      return res.status(409).json({ success: false, message: 'You have already applied for this job.' });
    }

    // Fetch job details to snapshot into application record
    let jobDetails = null;
    if (ObjectId.isValid(jobId)) {
      jobDetails = await jobsCollection.findOne({ _id: new ObjectId(jobId) });
    }

    const application = {
      ...req.body,
      jobId,
      jobTitle: jobDetails?.title || jobDetails?.jobTitle || req.body.jobTitle || 'Technical Position',
      jobType: jobDetails?.jobType || req.body.jobType || 'Full-time',
      companyId: jobDetails?.companyId || req.body.companyId || '',
      companyName: jobDetails?.companyName || req.body.companyName || 'TalentGrid Partner',
      companyLogo: jobDetails?.companyLogo || req.body.companyLogo || '',
      companyLocation: jobDetails?.location || req.body.location || '',
      applicantEmail: emailClean,
      applicantName: (applicantName || '').trim(),
      applicantPhone: req.body.applicantPhone || '',
      applicantLocation: req.body.applicantLocation || '',
      resumeUrl: resumeUrl || '',
      expectedSalary: expectedSalary || '',
      availability: availability || 'Immediate',
      coverLetter: coverLetter || '',
      status: 'pending',
      appliedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await applicationsCollection.insertOne(application);

    if (ObjectId.isValid(jobId)) {
      await jobsCollection.updateOne(
        { _id: new ObjectId(jobId) },
        { $inc: { applications: 1 } }
      );
    }

    res.status(201).json({
      success: true,
      message: 'Application submitted successfully!',
      applicationId: result.insertedId,
      totalApplied: userAppCount + 1,
      remainingFreeApps: isPro ? 'unlimited' : Math.max(0, 3 - (userAppCount + 1)),
    });
  } catch (error) {
    console.error('POST /api/applications error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// GET /api/applications — Get applications (supports case-insensitive email filter and auto-enrichment)
app.get('/api/applications', async (req, res) => {
  try {
    const { jobId, applicantEmail, email } = req.query;
    const targetEmail = (applicantEmail || email || '').trim();
    const filter = {};
    if (jobId) filter.jobId = jobId;
    if (targetEmail) {
      filter.applicantEmail = { $regex: `^${targetEmail}$`, $options: 'i' };
    }

    const applications = await applicationsCollection
      .find(filter)
      .sort({ appliedAt: -1, createdAt: -1 })
      .toArray();

    // Auto-enrich any older applications that might not have company/job fields populated
    const enriched = await Promise.all(
      applications.map(async (app) => {
        let jobInfo = null;
        let companyInfo = null;

        if ((!app.companyName || !app.jobTitle) && app.jobId && ObjectId.isValid(app.jobId)) {
          jobInfo = await jobsCollection.findOne({ _id: new ObjectId(app.jobId) });
        }
        if (!app.companyName && jobInfo?.companyId && ObjectId.isValid(jobInfo.companyId)) {
          companyInfo = await companiesCollection.findOne({ _id: new ObjectId(jobInfo.companyId) });
        }

        return {
          ...app,
          jobTitle: app.jobTitle || jobInfo?.title || jobInfo?.jobTitle || 'Technical Position',
          jobType: app.jobType || jobInfo?.jobType || 'Full-time',
          companyName: app.companyName || companyInfo?.name || jobInfo?.companyName || 'TalentGrid Partner',
          companyLogo: app.companyLogo || companyInfo?.logo || jobInfo?.companyLogo || '',
          location: app.companyLocation || companyInfo?.location || jobInfo?.location || app.applicantLocation || 'Remote',
        };
      })
    );

    res.status(200).json({ success: true, total: enriched.length, applications: enriched });
  } catch (error) {
    console.error('GET /api/applications error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch applications.' });
  }
});

// PATCH /api/applications/:id/status — Update applicant status
app.patch('/api/applications/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid application ID.' });
    }

    const validStatuses = ['pending', 'shortlisted', 'interviewing', 'rejected', 'hired'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status.' });
    }

    const appRecord = await applicationsCollection.findOne({ _id: new ObjectId(id) });
    if (!appRecord) {
      return res.status(404).json({ success: false, message: 'Application not found.' });
    }

    const result = await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status, updatedAt: new Date() } }
    );

    // Auto-create notification for the candidate
    if (appRecord.applicantEmail && notificationsCollection) {
      await notificationsCollection.insertOne({
        recipientEmail: appRecord.applicantEmail.toLowerCase(),
        title: `Application Status: ${status.toUpperCase()} ✨`,
        message: `Your application for ${appRecord.jobTitle || 'the position'} at ${appRecord.companyName || 'the employer'} was marked as ${status}.`,
        type: 'status_updated',
        link: '/dashboard/seeker/applications',
        isRead: false,
        createdAt: new Date(),
      });
    }

    res.status(200).json({ success: true, message: `Application marked as ${status}.` });
  } catch (error) {
    console.error('PATCH /api/applications/:id/status error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS ROUTES — /api/notifications
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/notifications — Fetch user notifications
app.get('/api/notifications', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ success: false, message: 'User email is required.' });
    }

    const notifications = await notificationsCollection
      .find({ recipientEmail: { $regex: `^${email.trim()}$`, $options: 'i' } })
      .sort({ createdAt: -1 })
      .limit(30)
      .toArray();

    const unreadCount = notifications.filter(n => !n.isRead).length;

    res.status(200).json({
      success: true,
      total: notifications.length,
      unreadCount,
      notifications,
    });
  } catch (error) {
    console.error('GET /api/notifications error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch notifications.' });
  }
});

// POST /api/notifications — Create a custom notification
app.post('/api/notifications', async (req, res) => {
  try {
    const { recipientEmail, title, message, type = 'info', link = '' } = req.body;
    if (!recipientEmail || !title || !message) {
      return res.status(400).json({ success: false, message: 'recipientEmail, title, and message are required.' });
    }

    const doc = {
      recipientEmail: recipientEmail.trim().toLowerCase(),
      title,
      message,
      type,
      link,
      isRead: false,
      createdAt: new Date(),
    };

    const result = await notificationsCollection.insertOne(doc);
    res.status(201).json({ success: true, message: 'Notification sent.', notificationId: result.insertedId });
  } catch (error) {
    console.error('POST /api/notifications error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// PATCH /api/notifications/:id/read — Mark single notification as read
app.patch('/api/notifications/:id/read', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid notification ID.' });
    }

    await notificationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { isRead: true, readAt: new Date() } }
    );

    res.status(200).json({ success: true, message: 'Notification marked as read.' });
  } catch (error) {
    console.error('PATCH /api/notifications/:id/read error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// PATCH /api/notifications/read-all — Mark all notifications as read for a user
app.patch('/api/notifications/read-all', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    await notificationsCollection.updateMany(
      { recipientEmail: { $regex: `^${email.trim()}$`, $options: 'i' }, isRead: false },
      { $set: { isRead: true, readAt: new Date() } }
    );

    res.status(200).json({ success: true, message: 'All notifications marked as read.' });
  } catch (error) {
    console.error('PATCH /api/notifications/read-all error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// DELETE /api/notifications/:id — Delete notification
app.delete('/api/notifications/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid notification ID.' });
    }

    await notificationsCollection.deleteOne({ _id: new ObjectId(id) });
    res.status(200).json({ success: true, message: 'Notification deleted.' });
  } catch (error) {
    console.error('DELETE /api/notifications/:id error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// SAVED JOBS (BOOKMARKS) ROUTES — /api/saved-jobs
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/saved-jobs — Get saved jobs for a seeker
app.get('/api/saved-jobs', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ success: false, message: 'User email is required.' });
    }

    const savedRecords = await savedJobsCollection
      .find({ userEmail: { $regex: `^${email.trim()}$`, $options: 'i' } })
      .sort({ savedAt: -1 })
      .toArray();

    // Enrich with live job details from jobsCollection
    const enriched = await Promise.all(
      savedRecords.map(async (record) => {
        let job = null;
        if (record.jobId && ObjectId.isValid(record.jobId)) {
          job = await jobsCollection.findOne({ _id: new ObjectId(record.jobId) });
        }
        return {
          ...record,
          job: job || record.cachedJob || null,
        };
      })
    );

    res.status(200).json({
      success: true,
      total: enriched.length,
      savedJobs: enriched.filter(r => r.job !== null),
      savedJobIds: savedRecords.map(r => r.jobId),
    });
  } catch (error) {
    console.error('GET /api/saved-jobs error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch saved jobs.' });
  }
});

// POST /api/saved-jobs — Toggle bookmark (save / unsave)
app.post('/api/saved-jobs', async (req, res) => {
  try {
    const { email, jobId } = req.body;
    if (!email || !jobId) {
      return res.status(400).json({ success: false, message: 'email and jobId are required.' });
    }

    const emailClean = email.trim().toLowerCase();
    const existing = await savedJobsCollection.findOne({
      userEmail: { $regex: `^${emailClean}$`, $options: 'i' },
      jobId,
    });

    if (existing) {
      // Unsave
      await savedJobsCollection.deleteOne({ _id: existing._id });
      return res.status(200).json({ success: true, isSaved: false, message: 'Job removed from saved list.' });
    } else {
      // Save
      let jobDetails = null;
      if (ObjectId.isValid(jobId)) {
        jobDetails = await jobsCollection.findOne({ _id: new ObjectId(jobId) });
      }

      await savedJobsCollection.insertOne({
        userEmail: emailClean,
        jobId,
        cachedJob: jobDetails ? {
          title: jobDetails.title,
          companyName: jobDetails.companyName,
          location: jobDetails.location,
          jobType: jobDetails.jobType,
          minSalary: jobDetails.minSalary,
          maxSalary: jobDetails.maxSalary,
        } : null,
        savedAt: new Date(),
      });

      return res.status(201).json({ success: true, isSaved: true, message: 'Job saved to your bookmarks!' });
    }
  } catch (error) {
    console.error('POST /api/saved-jobs error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// INTERVIEWS SCHEDULER ROUTES — /api/interviews
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/interviews — Schedule interview with candidate
app.post('/api/interviews', async (req, res) => {
  try {
    const { applicantEmail, recruiterEmail, candidateName, jobTitle, companyName, date, time, timezone, meetingLink, notes } = req.body;

    if (!applicantEmail || !jobTitle || !date || !time) {
      return res.status(400).json({ success: false, message: 'applicantEmail, jobTitle, date, and time are required.' });
    }

    const interviewDoc = {
      applicantEmail: applicantEmail.trim().toLowerCase(),
      recruiterEmail: (recruiterEmail || '').trim().toLowerCase(),
      candidateName: candidateName || 'Candidate',
      jobTitle,
      companyName: companyName || 'Employer',
      date,
      time,
      timezone: timezone || 'UTC',
      meetingLink: meetingLink || 'https://meet.google.com/new',
      notes: notes || '',
      status: 'scheduled',
      scheduledAt: new Date(),
    };

    const result = await interviewsCollection.insertOne(interviewDoc);

    // Create high-priority notification for the candidate
    if (notificationsCollection) {
      await notificationsCollection.insertOne({
        recipientEmail: applicantEmail.trim().toLowerCase(),
        title: `Interview Scheduled! 📅`,
        message: `${companyName || 'The employer'} invited you for an interview for "${jobTitle}" on ${date} at ${time} (${timezone || 'UTC'}).`,
        type: 'interview',
        link: meetingLink || '/dashboard/seeker/applications',
        isRead: false,
        createdAt: new Date(),
      });
    }

    res.status(201).json({
      success: true,
      message: 'Interview invitation sent successfully!',
      interviewId: result.insertedId,
    });
  } catch (error) {
    console.error('POST /api/interviews error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// GET /api/interviews — Get scheduled interviews
app.get('/api/interviews', async (req, res) => {
  try {
    const { email, role } = req.query;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    const emailClean = email.trim().toLowerCase();
    const filter = role === 'recruiter'
      ? { recruiterEmail: { $regex: `^${emailClean}$`, $options: 'i' } }
      : { applicantEmail: { $regex: `^${emailClean}$`, $options: 'i' } };

    const interviews = await interviewsCollection
      .find(filter)
      .sort({ scheduledAt: -1 })
      .toArray();

    res.status(200).json({ success: true, total: interviews.length, interviews });
  } catch (error) {
    console.error('GET /api/interviews error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch interviews.' });
  }
});

// GET /api/subscriptions — Get subscription status for a user
app.get('/api/subscriptions', async (req, res) => {
  try {
    const { email, userId } = req.query;
    if (!email && !userId) {
      return res.status(400).json({ success: false, message: 'Email or userId is required.' });
    }

    const filter = email
      ? { userEmail: { $regex: `^${email.trim()}$`, $options: 'i' } }
      : { userId };

    const subscription = await subscriptionsCollection.findOne(filter);

    res.status(200).json({
      success: true,
      subscription: subscription || {
        plan: 'free',
        status: 'active',
        userEmail: email || '',
      },
    });
  } catch (error) {
    console.error('GET /api/subscriptions error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch subscription.' });
  }
});

// GET /api/seeker/profile — Get seeker profile from users collection
app.get('/api/seeker/profile', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    const user = await usersCollection.findOne(
      { email: { $regex: `^${email.trim()}$`, $options: 'i' } },
      { projection: { password: 0, hashedPassword: 0 } }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'User profile not found.' });
    }

    res.status(200).json({ success: true, profile: user });
  } catch (error) {
    console.error('GET /api/seeker/profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch profile.' });
  }
});

// PATCH /api/seeker/profile — Update seeker profile fields
app.patch('/api/seeker/profile', async (req, res) => {
  try {
    const { email, ...updateFields } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required.' });
    }

    // Remove sensitive fields from updates
    delete updateFields.password;
    delete updateFields.hashedPassword;
    delete updateFields.role;

    const result = await usersCollection.updateOne(
      { email: { $regex: `^${email.trim()}$`, $options: 'i' } },
      { 
        $set: { 
          ...updateFields, 
          email: email.trim().toLowerCase(),
          updatedAt: new Date() 
        },
        $setOnInsert: {
          createdAt: new Date(),
          role: 'job_seeker'
        }
      },
      { upsert: true }
    );

    res.status(200).json({ success: true, message: 'Profile updated successfully.' });
  } catch (error) {
    console.error('PATCH /api/seeker/profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to update profile.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// SEEKER SPECIFIC ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/seeker/applications — Enriched with company details
app.get('/api/seeker/applications', async (req, res) => {
  try {
    const email = req.query.email || req.cookies?.hl_user_email;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Applicant email is required.' });
    }

    const applications = await applicationsCollection
      .find({ applicantEmail: email })
      .sort({ appliedAt: -1 })
      .toArray();

    const enriched = await Promise.all(
      applications.map(async (app) => {
        let jobInfo = null;
        let companyInfo = null;

        if (app.jobId && ObjectId.isValid(app.jobId)) {
          jobInfo = await jobsCollection.findOne({ _id: new ObjectId(app.jobId) });
        }
        if (jobInfo?.companyId && ObjectId.isValid(jobInfo.companyId)) {
          companyInfo = await companiesCollection.findOne({ _id: new ObjectId(jobInfo.companyId) });
        }

        return {
          ...app,
          jobTitle: jobInfo?.title || jobInfo?.jobTitle || app.jobTitle || 'Position',
          jobType: jobInfo?.jobType || 'Full-time',
          companyName: companyInfo?.name || jobInfo?.companyName || app.companyName || 'Company',
          companyLogo: companyInfo?.logo || jobInfo?.companyLogo || app.companyLogo || '',
          location: companyInfo?.location || jobInfo?.location || 'Remote',
        };
      })
    );

    res.status(200).json({ success: true, total: enriched.length, applications: enriched });
  } catch (error) {
    console.error('GET /api/seeker/applications error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch seeker applications.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN SPECIFIC ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/admin/users — Only accessible by Admin
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await usersCollection
      .find({}, { projection: { password: 0, hashedPassword: 0 } })
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({ success: true, total: users.length, users });
  } catch (error) {
    console.error('GET /api/admin/users error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// PATCH /api/companies/:id/status — Admin approves/rejects company
app.patch('/api/companies/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNote } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid company ID.' });
    }

    const valid = ['approved', 'rejected', 'pending', 'suspended'];
    if (!valid.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status.' });
    }

    const result = await companiesCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status,
          isApproved: status === 'approved',
          adminNote: adminNote || '',
          reviewedAt: new Date(),
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: 'Company not found.' });
    }

    res.status(200).json({ success: true, message: `Company status updated to ${status}.` });
  } catch (error) {
    console.error('PATCH /api/companies/:id/status error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// COMPANIES ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/companies — Create company profile
app.post('/api/companies', async (req, res) => {
  try {
    const {
      name,
      websiteUrl,
      website,
      industry,
      location,
      employCount,
      size,
      description,
      logo,
      recruiterId,
      recruiterEmail,
    } = req.body;

    if (!name || name.trim() === '') {
      return res.status(400).json({
        success: false,
        message: 'Company name is required.',
      });
    }

    const finalWebsite = (websiteUrl || website || '').trim();
    const finalEmployCount = (employCount || size || '11-50 employees').trim();
    const finalRecruiterId = recruiterId || recruiterEmail || '';

    const newCompany = {
      name: name.trim(),
      websiteUrl: finalWebsite,
      website: finalWebsite,
      industry: (industry || 'Technology').trim(),
      location: (location || '').trim(),
      employCount: finalEmployCount,
      size: finalEmployCount,
      description: (description || '').trim(),
      logo: (logo || '').trim(),
      recruiterId: finalRecruiterId,
      recruiterEmail: (recruiterEmail || recruiterId || '').trim(),
      status: 'pending',
      isApproved: false,
      activeJobsCount: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await companiesCollection.insertOne(newCompany);
    const createdCompany = { ...newCompany, _id: result.insertedId };

    res.status(201).json({
      success: true,
      message: 'Company profile submitted for admin approval!',
      companyId: result.insertedId,
      company: createdCompany,
    });
  } catch (error) {
    console.error('POST /api/companies error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// GET /api/companies — Get all companies
app.get('/api/companies', async (req, res) => {
  try {
    const { recruiterEmail, recruiterId, isApproved, status, search, industry, size, limit } = req.query;

    const filter = {};
    if (recruiterEmail) filter.recruiterEmail = recruiterEmail;
    if (recruiterId) filter.recruiterId = recruiterId;
    if (status && status !== 'all') filter.status = status;
    if (isApproved !== undefined && isApproved !== '') filter.isApproved = isApproved === 'true';
    if (industry) filter.industry = { $regex: industry, $options: 'i' };
    if (size) filter.size = { $regex: size, $options: 'i' };
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { industry: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
      ];
    }

    let query = companiesCollection.find(filter).sort({ createdAt: -1 });
    if (limit) query = query.limit(parseInt(limit));

    const companies = await query.toArray();
    res.status(200).json({ success: true, total: companies.length, companies });
  } catch (error) {
    console.error('GET /api/companies error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch companies.' });
  }
});

// GET /api/companies/:id — Get single company
app.get('/api/companies/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid company ID.' });
    }

    const company = await companiesCollection.findOne({ _id: new ObjectId(id) });
    if (!company) {
      return res.status(404).json({ success: false, message: 'Company not found.' });
    }

    const jobsCount = await jobsCollection.countDocuments({
      companyId: id,
      status: 'active',
    });

    res.status(200).json({
      success: true,
      company: { ...company, activeJobsCount: jobsCount },
    });
  } catch (error) {
    console.error('GET /api/companies/:id error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// PATCH /api/companies/:id — Update company
app.patch('/api/companies/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid company ID.' });
    }

    const updates = { ...req.body, updatedAt: new Date() };
    delete updates._id;
    delete updates.recruiterEmail;
    delete updates.isApproved;

    if (updates.websiteUrl || updates.website) {
      const web = updates.websiteUrl || updates.website;
      updates.websiteUrl = web;
      updates.website = web;
    }
    if (updates.employCount || updates.size) {
      const emp = updates.employCount || updates.size;
      updates.employCount = emp;
      updates.size = emp;
    }

    const result = await companiesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: 'Company not found.' });
    }

    res.status(200).json({ success: true, message: 'Company profile updated successfully.' });
  } catch (error) {
    console.error('PATCH /api/companies/:id error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// DELETE /api/companies/:id — Delete company
app.delete('/api/companies/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid company ID.' });
    }

    const result = await companiesCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: 'Company not found.' });
    }

    res.status(200).json({ success: true, message: 'Company deleted successfully.' });
  } catch (error) {
    console.error('DELETE /api/companies/:id error:', error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// STRIPE PAYMENT & CHECKOUT ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/create-checkout-session — Create a Stripe Checkout Session
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const { planId, planName, priceAmount, billingCycle, userEmail, userId } = req.body;

    if (!stripe) {
      return res.status(500).json({ success: false, message: 'Stripe secret key is missing on server.' });
    }

    const clientOrigin = req.headers.origin || 'http://localhost:3000';
    const numericPrice = parseFloat(String(priceAmount).replace(/[^0-9.]/g, '')) || 17;
    const unitAmount = Math.round(numericPrice * 100);

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `HireLoop ${planName || 'Growth'} Plan (${billingCycle || 'monthly'})`,
              description: 'Unlimited Job Applications + Verified Candidate Badge + Priority Processing',
            },
            unit_amount: unitAmount,
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${clientOrigin}/plans?payment_success=true&session_id={CHECKOUT_SESSION_ID}&plan=${planId || 'growth'}`,
      cancel_url: `${clientOrigin}/plans?payment_canceled=true`,
      customer_email: userEmail || undefined,
      metadata: {
        planId: planId || 'growth',
        planName: planName || 'Growth',
        userEmail: userEmail || '',
        userId: userId || '',
      },
    });

    res.status(200).json({
      success: true,
      url: session.url,
      sessionId: session.id,
    });
  } catch (error) {
    console.error('POST /api/create-checkout-session error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to create Stripe checkout session.' });
  }
});

// GET /api/verify-checkout-session — Verify payment status
app.get('/api/verify-checkout-session', async (req, res) => {
  try {
    const { sessionId } = req.query;
    if (!sessionId) {
      return res.status(400).json({ success: false, message: 'Session ID is required.' });
    }

    if (!stripe) {
      return res.status(500).json({ success: false, message: 'Stripe is not configured on server.' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status === 'paid' || session.status === 'complete') {
      const userEmail = session.customer_email || session.metadata?.userEmail;
      const planId = session.metadata?.planId || 'growth';

      if (userEmail) {
        await subscriptionsCollection.updateOne(
          { userEmail },
          {
            $set: {
              userEmail,
              plan: planId,
              status: 'active',
              stripeSessionId: session.id,
              stripePaymentIntent: session.payment_intent,
              amountPaid: session.amount_total ? session.amount_total / 100 : 0,
              currency: session.currency,
              updatedAt: new Date(),
            },
          },
          { upsert: true }
        );

        await usersCollection.updateOne(
          { email: userEmail },
          { $set: { plan: planId, planStatus: 'active', updatedAt: new Date() } }
        );
      }

      return res.status(200).json({
        success: true,
        isPaid: true,
        planId,
        userEmail,
      });
    }

    return res.status(200).json({ success: true, isPaid: false, status: session.payment_status });
  } catch (error) {
    console.error('GET /api/verify-checkout-session error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to verify payment session.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ROOT & HEALTH CHECK ROUTES
// ═══════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({
    message: '🚀 TalentGrid API Server is running on Vercel & Node!',
    version: '1.0.0',
    status: 'healthy',
    endpoints: {
      jobs: '/api/jobs',
      applications: '/api/applications',
      companies: '/api/companies',
      seeker: '/api/seeker/applications',
      admin: '/api/admin/users',
    },
  });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime(), timestamp: new Date() });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ success: false, message: 'Something went wrong.' });
});

// Only listen when executed directly in standalone/local mode
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`🚀 TalentGrid server is running on port ${port}`);
  });
}

// Export for Vercel Serverless Function
module.exports = app;