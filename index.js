

const { getAuth } = require("firebase-admin/auth");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();

const stripe = require("stripe")(process.env.STRIPE_SECRET);

const app = express();
const port = process.env.PORT || 3000;

// =========================
//  FIREBASE ADMIN INIT
// =========================
if (!admin.apps.length) {
  const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8");
  const serviceAccount = JSON.parse(decoded);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log("Firebase Admin Initialized");
}

// =========================
//  GLOBAL MIDDLEWARES
// =========================
const FRONTEND_ORIGIN = process.env.SITE_DOMAIN;

app.use(
  cors({
    origin: ["http://localhost:5173", "http://127.0.0.1:5173", FRONTEND_ORIGIN],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.use(express.json());

// =========================
//  MONGODB - Persistent connection (Vercel safe)
// =========================
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.at3dlqg.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let isConnected = false;

async function connectDB() {
  if (!isConnected) {
    await client.connect();
    isConnected = true;
    console.log("Connected to MongoDB");
  }
}

// Collections (accessed after connect)
const db = client.db("public_Infrastructure_user");
const usersCollection = db.collection("users");
const issuesCollection = db.collection("issues");
const paymentsCollection = db.collection("payments");
const staffCollection = db.collection("staff");

// Ensure DB connected before every request
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error("DB connection error:", err);
    res.status(500).send({ message: "Database connection failed" });
  }
});

// =========================
//  VERIFY FIREBASE TOKEN
// =========================
const verifyFbToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.decoded_email = decoded.email;
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).send({ message: "Invalid Token" });
  }
};

// =========================
//  VERIFY ADMIN
// =========================
async function verifyAdmin(req, res, next) {
  try {
    if (!req.decoded_email) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    const adminUser = await usersCollection.findOne({ email: req.decoded_email });
    if (!adminUser || adminUser.role !== "admin") {
      return res.status(403).send({ message: "Forbidden: admin only" });
    }
    next();
  } catch (err) {
    console.error("verifyAdmin error:", err);
    res.status(500).send({ message: "Internal server error" });
  }
}

// =========================
//  VERIFY STAFF
// =========================
async function verifyStaff(req, res, next) {
  try {
    if (!req.decoded_email) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    const staffUser = await usersCollection.findOne({ email: req.decoded_email });
    if (!staffUser || staffUser.role !== "staff") {
      return res.status(403).send({ message: "Forbidden: staff only" });
    }
    next();
  } catch (err) {
    console.error("verifyStaff error:", err);
    res.status(500).send({ message: "Internal server error" });
  }
}

// =========================
//  TIMELINE HELPER
// =========================
async function addTimelineEntry(issueId, entry) {
  if (!ObjectId.isValid(issueId)) throw new Error("Invalid issueId");
  const timelineItem = {
    status: entry.status || null,
    message: entry.message || "",
    updatedBy: entry.updatedBy || "System",
    role: entry.role || "System",
    date: new Date(),
  };
  return issuesCollection.updateOne(
    { _id: new ObjectId(issueId) },
    { $push: { timeline: timelineItem } }
  );
}

// =========================
//  ROUTES
// =========================

// Health check
app.get("/", (req, res) => {
  res.send("Backend is running successfully!,welcome to my Final Website");
});

// Token
app.post("/set-token", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send("Missing Authorization");
    const token = authHeader.split(" ")[1];
    if (!token) return res.status(401).send("Invalid token");
    res.cookie("fbToken", token, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24,
    });
    res.send({ message: "Token cookie set" });
  } catch (err) {
    res.status(500).send("Failed to set cookie");
  }
});

// ------------------------
// USERS
// ------------------------
app.get("/users", verifyFbToken, async (req, res) => {
  try {
    const searchText = req.query.searchText;
    const query = {};
    if (searchText) {
      query.$or = [
        { displayName: { $regex: searchText, $options: "i" } },
        { email: { $regex: searchText, $options: "i" } },
      ];
    }
    const result = await usersCollection.find(query).limit(5).toArray();
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/users/:email/role", verifyFbToken, async (req, res) => {
  try {
    const email = req.params.email;
    if (email !== req.decoded_email) {
      return res.status(403).send({ message: "Forbidden" });
    }
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });
    res.send({ role: user.role || "citizen" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.patch("/users/:email/role", verifyFbToken, async (req, res) => {
  try {
    const { role } = req.body;
    const email = req.params.email;
    if (!["citizen", "staff", "admin"].includes(role)) {
      return res.status(400).send({ message: "Invalid role" });
    }
    const result = await usersCollection.updateOne({ email }, { $set: { role } });
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "User not found" });
    }
    res.send({ message: "User role updated" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/users", async (req, res) => {
  try {
    const user = req.body;
    user.role = "citizen";
    user.createdAt = new Date();
    const existing = await usersCollection.findOne({ email: user.email });
    if (existing) {
      return res.status(409).send({ message: "User already exists" });
    }
    const result = await usersCollection.insertOne(user);
    res.status(201).send({ message: "User created successfully", insertedId: result.insertedId });
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// ------------------------
// DASHBOARD - CITIZEN
// ------------------------
app.get("/dashboard/citizen/:email", verifyFbToken, async (req, res) => {
  try {
    const email = req.params.email;
    const totalIssues = await issuesCollection.countDocuments({ userEmail: email });
    const pending = await issuesCollection.countDocuments({ userEmail: email, status: "Pending" });
    const inProgress = await issuesCollection.countDocuments({ userEmail: email, status: "In-Progress" });
    const resolved = await issuesCollection.countDocuments({ userEmail: email, status: "Resolved" });
    const totalPayments = await paymentsCollection
      .aggregate([{ $match: { email } }, { $group: { _id: null, total: { $sum: "$amount" } } }])
      .toArray();
    res.send({ totalIssues, pending, inProgress, resolved, totalPayments: totalPayments[0]?.total || 0 });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// ------------------------
// PROFILE
// ------------------------
app.get("/profile", verifyFbToken, async (req, res) => {
  try {
    const email = req.query.email || "testuser@example.com";
    let user = await usersCollection.findOne({ email: { $regex: `^${email}$`, $options: "i" } });
    if (!user) {
      const newUser = {
        email,
        displayName: email.split("@")[0],
        photoURL: "https://i.pravatar.cc/150?u=" + encodeURIComponent(email),
        isPremium: false,
        isBlocked: false,
      };
      await usersCollection.insertOne(newUser);
      user = newUser;
    }
    res.send(user);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.patch("/profile", verifyFbToken, async (req, res) => {
  try {
    const email = req.decoded_email;
    const updates = req.body;
    if (!email) return res.status(400).send({ message: "Email missing" });
    const result = await usersCollection.updateOne({ email }, { $set: updates });
    if (result.modifiedCount === 0) return res.status(400).send({ message: "Nothing updated" });
    const updatedUser = await usersCollection.findOne({ email });
    res.send(updatedUser);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// ------------------------
// ADMIN
// ------------------------
app.get("/admin/stats", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const totalIssues = await issuesCollection.countDocuments();
    const resolved = await issuesCollection.countDocuments({ status: "Resolved" });
    const pending = await issuesCollection.countDocuments({ status: "Pending" });
    const rejected = await issuesCollection.countDocuments({ status: "Closed" });
    const paymentsAgg = await paymentsCollection
      .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
      .toArray();
    const totalPayments = paymentsAgg[0]?.total || 0;
    const latestIssues = await issuesCollection.find().sort({ createdAt: -1 }).limit(6).toArray();
    const latestPayments = await paymentsCollection.find().sort({ createdAt: -1 }).limit(6).toArray();
    const latestUsers = await usersCollection.find().sort({ createdAt: -1 }).limit(6).toArray();
    res.send({ totalIssues, resolved, pending, rejected, totalPayments, latestIssues, latestPayments, latestUsers });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/admin/issues", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page || "1", 10);
    const limit = parseInt(req.query.limit || "20", 10);
    const skip = (page - 1) * limit;
    const issues = await issuesCollection.find().sort({ priority: 1, createdAt: -1 }).skip(skip).limit(limit).toArray();
    const total = await issuesCollection.countDocuments();
    res.send({ issues, total, page, limit });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/admin/issues/:id/assign", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const issueId = req.params.id;
    const { staffEmail, staffName } = req.body;
    if (!ObjectId.isValid(issueId)) return res.status(400).send({ message: "Invalid issue id" });
    if (!staffEmail) return res.status(400).send({ message: "Missing staffEmail" });
    const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    if (issue.assignedTo) return res.status(400).send({ message: "Already assigned" });
    await issuesCollection.updateOne(
      { _id: new ObjectId(issueId) },
      { $set: { assignedTo: { email: staffEmail, name: staffName || null }, status: "In-Progress" } }
    );
    await addTimelineEntry(issueId, {
      status: "In-Progress",
      message: `Issue assigned to Staff: ${staffName || staffEmail}`,
      updatedBy: req.decoded_email,
      role: "Admin",
    });
    res.send({ message: "Staff assigned" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/admin/issues/:id/reject", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const issueId = req.params.id;
    const { reason } = req.body;
    const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    if (issue.status !== "Pending") return res.status(400).send({ message: "Only pending issues can be rejected" });
    await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, { $set: { status: "Closed" } });
    await addTimelineEntry(issueId, {
      status: "Closed",
      message: `Issue rejected by admin. Reason: ${reason || "Not specified"}`,
      updatedBy: req.decoded_email,
      role: "Admin",
    });
    res.send({ message: "Issue rejected" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/admin/users", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const users = await usersCollection.find({ role: { $ne: "admin" } }).toArray();
    res.send(users);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.patch("/admin/users/:email/block", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const email = req.params.email;
    const { block } = req.body;
    const result = await usersCollection.updateOne({ email }, { $set: { isBlocked: !!block } });
    res.send({ modified: result.modifiedCount ? true : false });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.patch("/admin/users/:email/make-admin", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const email = req.params.email;
    const result = await usersCollection.updateOne({ email }, { $set: { role: "admin" } });
    if (result.matchedCount === 0) return res.status(404).send({ message: "User not found" });
    res.send({ message: "User promoted to admin" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/admin/payments", verifyFbToken, verifyAdmin, async (req, res) => {
  try {
    const payments = await paymentsCollection.find().sort({ createdAt: -1 }).toArray();
    res.send(payments);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// ------------------------
// ADMIN STAFF
// ------------------------
app.get("/admin/staff", verifyFbToken, verifyAdmin, async (req, res) => {
  const staffList = await staffCollection.find().toArray();
  res.send(staffList);
});

app.post("/admin/staff", verifyFbToken, verifyAdmin, async (req, res) => {
  const { name, email, phone, photo, password, region, district } = req.body;
  try {
    await admin.auth().createUser({ email, password, displayName: name, photoURL: photo || null });
    const commonUserData = { name, email, phone: phone || "", photo: photo || "", role: "staff", createdAt: new Date() };
    await usersCollection.insertOne(commonUserData);
    const staffSpecific = { ...commonUserData, region, district, experience: req.body.experience || "0", status: req.body.status || "Accepted" };
    await staffCollection.insertOne(staffSpecific);
    res.status(201).json({ message: "Staff added successfully" });
  } catch (error) {
    console.error("POST /admin/staff error:", error);
    res.status(500).json({ message: "Failed to add staff", error: error.message });
  }
});

app.patch("/admin/staff/:id", verifyFbToken, verifyAdmin, async (req, res) => {
  const staffIdString = req.params.id;
  const updateData = req.body;
  delete updateData.email;
  delete updateData.role;
  delete updateData._id;
  try {
    const staffObjectId = new ObjectId(staffIdString);
    const updateDoc = { $set: { ...updateData, updatedAt: new Date() } };
    const staffUpdateResult = await staffCollection.updateOne({ _id: staffObjectId }, updateDoc);
    const userUpdateResult = await usersCollection.updateOne({ _id: staffObjectId }, updateDoc);
    if (staffUpdateResult.modifiedCount === 0 && userUpdateResult.modifiedCount === 0) {
      const matched = staffUpdateResult.matchedCount > 0 || userUpdateResult.matchedCount > 0;
      if (!matched) return res.status(404).send({ message: "Staff member not found in the database." });
      return res.send({ message: "Staff member found, but no changes were applied." });
    }
    res.send({ message: "Staff updated successfully" });
  } catch (e) {
    res.status(500).send({ message: "Failed to update staff due to a database error." });
  }
});

app.delete("/admin/staff/:id", verifyFbToken, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  await staffCollection.deleteOne({ _id: id });
  res.send({ message: "Staff deleted successfully" });
});

// ------------------------
// SUBSCRIPTION
// ------------------------
app.post("/subscribe", verifyFbToken, async (req, res) => {
  const email = req.decoded_email;
  if (!email) return res.status(400).send({ message: "Email missing" });
  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(404).send({ message: "User not found" });
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [{ price_data: { currency: "usd", unit_amount: 1000, product_data: { name: "Premium Subscription" } }, quantity: 1 }],
      customer_email: email,
      success_url: `${process.env.SITE_DOMAIN}/subscribe-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.SITE_DOMAIN}/profile`,
    });
    return res.send({ url: session.url });
  } catch (err) {
    return res.status(500).send({ message: "Stripe Error", error: err.message });
  }
});

app.get("/subscribe-success", async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    if (!sessionId) return res.status(400).send({ message: "Missing session_id" });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const email = session.customer_email;
    if (!email) return res.status(400).send({ message: "Customer email missing" });
    await usersCollection.updateOne({ email }, { $set: { isPremium: true, subscriptionDate: new Date() } });
    await paymentsCollection.insertOne({ email, amount: session.amount_total / 100, currency: session.currency, createdAt: new Date(), sessionId });
    res.send({ message: "Subscription successful", email, isPremium: true });
  } catch (err) {
    res.status(500).send({ message: "Subscription success failed", error: err.message });
  }
});

// ------------------------
// ISSUES
// ------------------------
app.post("/issues", verifyFbToken, async (req, res) => {
  try {
    const { title, description, category, image, reporterRegion, reporterDistrict } = req.body;
    if (!title || !description || !category || !reporterRegion || !reporterDistrict) {
      return res.status(400).send({ message: "Missing required fields" });
    }
    const issue = {
      title, description, category, image: image || "", reporterRegion, reporterDistrict,
      userEmail: req.decoded_email, createdAt: new Date(), status: "Pending", priority: "Normal", upvotes: 0,
      timeline: [{ status: "Pending", message: "Issue reported by citizen", updatedBy: req.decoded_email, role: "Citizen", date: new Date() }],
    };
    const result = await issuesCollection.insertOne(issue);
    res.status(201).send({ message: "Issue created successfully", insertedId: result.insertedId });
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/issues", async (req, res) => {
  try {
    const { search, status, category, priority, page, limit } = req.query;
    const pageNumber = parseInt(page) || 1;
    const limitNumber = parseInt(limit) || 9;
    const skip = (pageNumber - 1) * limitNumber;
    let queryFilter = {};
    if (status) queryFilter.status = status;
    if (category) queryFilter.category = category;
    if (priority) queryFilter.priority = priority;
    if (search) {
      const searchRegex = new RegExp(search, "i");
      queryFilter.$or = [
        { title: { $regex: searchRegex } },
        { description: { $regex: searchRegex } },
        { reporterDistrict: { $regex: searchRegex } },
        { reporterRegion: { $regex: searchRegex } },
      ];
    }
    const issues = await issuesCollection.find(queryFilter).sort({ priority: -1, createdAt: -1 }).skip(skip).limit(limitNumber).toArray();
    const totalIssues = await issuesCollection.countDocuments(queryFilter);
    res.send({ issues, totalIssues });
  } catch (e) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/issues/my-issues", verifyFbToken, async (req, res) => {
  try {
    const email = req.decoded_email;
    const issues = await issuesCollection.find({ userEmail: email }).sort({ createdAt: -1 }).toArray();
    res.status(200).send(issues);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/issues/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid issue ID" });
    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    res.send(issue);
  } catch (err) {
    res.status(500).send({ message: "Internal Server Error" });
  }
});

app.patch("/issues/:id", verifyFbToken, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });
    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    if (issue.userEmail !== req.decoded_email) return res.status(403).send({ message: "Forbidden: only owner can edit this issue" });
    if (issue.status !== "Pending") return res.status(400).send({ message: "Only pending issues can be edited" });
    const { title, description, category, image } = req.body;
    const updateDoc = { $set: { ...(title && { title }), ...(description && { description }), ...(category && { category }), ...(image && { image }), updatedAt: new Date() } };
    await issuesCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);
    res.status(200).send({ message: "Issue updated successfully" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.delete("/issues/:id", verifyFbToken, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid ID" });
    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    if (issue.userEmail !== req.decoded_email) return res.status(403).send({ message: "Forbidden: only owner can delete this issue" });
    await issuesCollection.deleteOne({ _id: new ObjectId(id) });
    res.status(200).send({ message: "Issue deleted successfully" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/issues/:id/assign", async (req, res) => {
  try {
    const issueId = req.params.id;
    const { staffEmail, staffName } = req.body;
    if (!ObjectId.isValid(issueId)) return res.status(400).send({ message: "Invalid issue id" });
    if (!staffEmail) return res.status(400).send({ message: "Missing staff email" });
    await issuesCollection.updateOne(
      { _id: new ObjectId(issueId) },
      { $set: { assignedTo: { email: staffEmail, name: staffName || null }, status: "In-Progress" } }
    );
    await addTimelineEntry(issueId, { status: "In-Progress", message: `Issue assigned to Staff: ${staffName || staffEmail}`, updatedBy: req.decoded_email, role: "Admin" });
    res.send({ message: "Staff assigned and timeline updated" });
  } catch (err) {
    res.status(500).send({ message: "Assignment failed", error: err.message });
  }
});

app.post("/issues/:id/status", async (req, res) => {
  try {
    const issueId = req.params.id;
    const { status, note } = req.body;
    const allowed = ["Pending", "In-Progress", "Resolved", "Closed"];
    if (!allowed.includes(status)) return res.status(400).send({ message: "Invalid status" });
    await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, { $set: { status } });
    await addTimelineEntry(issueId, { status, message: note || `Status changed to ${status}`, updatedBy: req.decoded_email, role: "Staff" });
    res.send({ message: "Status updated and timeline entry added" });
  } catch (err) {
    res.status(500).send({ message: "Status update failed", error: err.message });
  }
});

app.post("/issues/:id/reject", async (req, res) => {
  try {
    const issueId = req.params.id;
    const { reason } = req.body;
    await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, { $set: { status: "Closed" } });
    await addTimelineEntry(issueId, { status: "Closed", message: `Issue rejected by admin. Reason: ${reason || "Not specified"}`, updatedBy: req.decoded_email, role: "Admin" });
    res.send({ message: "Issue rejected and closed" });
  } catch (err) {
    res.status(500).send({ message: "Reject failed", error: err.message });
  }
});

app.patch("/issues/upvote/:id", async (req, res) => {
  try {
    const issueId = req.params.id;
    const userEmail = req.decoded_email;
    const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    if (issue.userEmail === userEmail) return res.status(400).send({ message: "You cannot upvote your own issue" });
    const hasVoted = await issuesCollection.findOne({ _id: new ObjectId(issueId), upvotedUsers: userEmail });
    if (hasVoted) return res.status(400).send({ message: "You have already upvoted this issue" });
    await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, { $inc: { upvotes: 1 }, $push: { upvotedUsers: userEmail } });
    await addTimelineEntry(issueId, { status: issue.status || "Pending", message: `Issue upvoted by ${userEmail}`, updatedBy: userEmail, role: "Citizen" });
    res.status(200).send({ message: "Upvoted successfully" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.patch("/issues/:id/status", verifyFbToken, async (req, res) => {
  try {
    const { status } = req.body;
    const issueId = req.params.id;
    const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    if (issue.assignedStaff?.email !== req.decoded_email) return res.status(403).send({ message: "Forbidden" });
    const allowed = { Pending: ["In-Progress"], "In-Progress": ["Working"], Working: ["Resolved"], Resolved: ["Closed"] };
    if (!allowed[issue.status]?.includes(status)) return res.status(400).send({ message: "Invalid status transition" });
    await issuesCollection.updateOne(
      { _id: new ObjectId(issueId) },
      { $set: { status }, $push: { timeline: { status, message: `Status changed to ${status}`, updatedBy: req.decoded_email, role: "Staff", date: new Date() } } }
    );
    res.send({ message: "Status updated successfully" });
  } catch (err) {
    res.status(500).send({ message: "Status update failed" });
  }
});

// ------------------------
// PAYMENTS / BOOST
// ------------------------
app.post("/create-boost-session", verifyFbToken, async (req, res) => {
  try {
    const { issueId, cost, title, userEmail } = req.body;
    if (!issueId || !cost || !title || !userEmail) return res.status(400).json({ message: "Missing required fields" });
    if (userEmail !== req.decoded_email) return res.status(403).json({ message: "Forbidden access" });
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [{ price_data: { currency: "usd", unit_amount: parseInt(cost, 10) * 100, product_data: { name: `Boost Issue: ${title}` } }, quantity: 1 }],
      mode: "payment",
      metadata: { issueId, title },
      customer_email: userEmail,
      success_url: `${process.env.SITE_DOMAIN}/boost-success?session_id={CHECKOUT_SESSION_ID}&issueId=${issueId}`,
      cancel_url: `${process.env.SITE_DOMAIN}/issue/${issueId}`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ message: "Stripe session failed", error: err.message });
  }
});

app.get("/boost-success", verifyFbToken, async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    if (!sessionId) return res.status(400).send({ message: "Missing session_id" });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const issueId = session.metadata && session.metadata.issueId;
    const title = session.metadata && session.metadata.title;
    const email = session.customer_email;
    if (!issueId) return res.status(400).send({ message: "Missing issueId in session metadata" });
    if (!ObjectId.isValid(issueId)) return res.status(400).send({ message: "Invalid issueId" });
    await issuesCollection.updateOne({ _id: new ObjectId(issueId) }, { $set: { priority: "High" } });
    await paymentsCollection.insertOne({ issueId, title, email, amount: session.amount_total ? session.amount_total / 100 : null, currency: session.currency || null, paymentStatus: session.payment_status || null, transactionId: session.id, createdAt: new Date() });
    await addTimelineEntry(issueId, { status: null, message: "Issue boosted by payment", updatedBy: email, role: "Citizen" });
    res.send({ message: "Payment Success — Issue Boosted", issueId, email, status: "success" });
  } catch (err) {
    res.status(500).send({ message: "Boost success failed", error: err.message });
  }
});

app.get("/payments", verifyFbToken, async (req, res) => {
  try {
    const email = req.decoded_email;
    const payments = await paymentsCollection.find({ email }).sort({ createdAt: -1 }).toArray();
    res.send(payments);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// ------------------------
// STAFF
// ------------------------
app.get("/staff", verifyFbToken, async (req, res) => {
  try {
    const staffList = await staffCollection.find().toArray();
    res.send(staffList);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.post("/staff", verifyFbToken, async (req, res) => {
  try {
    const staffData = req.body;
    const requiredFields = ["name", "email", "phone", "region", "district"];
    for (const field of requiredFields) {
      if (!staffData[field]) return res.status(400).send({ message: `${field} is required` });
    }
    delete staffData._id;
    if (!staffData.status) staffData.status = "Accepted";
    if (!staffData.experience) staffData.experience = "0";
    staffData.submittedAt = new Date();
    staffData.timeline = [{ status: staffData.status, message: "Staff member created by Admin.", updatedBy: req.decoded_email, role: "Admin", date: new Date() }];
    const result = await staffCollection.insertOne(staffData);
    res.status(201).send({ message: "Staff member added successfully", insertedId: result.insertedId });
  } catch (err) {
    res.status(500).send({ message: "Internal server error", error: err.message });
  }
});

app.patch("/staff/:email", verifyFbToken, async (req, res) => {
  try {
    const { status } = req.body;
    const email = req.params.email;
    if (!["Pending", "Accepted", "Rejected"].includes(status)) return res.status(400).send({ message: "Invalid status" });
    const result = await staffCollection.updateOne({ email }, { $set: { status } });
    if (result.matchedCount === 0) return res.status(404).send({ message: "Staff not found" });
    res.send({ message: "Staff status updated" });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.patch("/staff/issues/:id/status", verifyFbToken, async (req, res) => {
  try {
    const issueId = req.params.id;
    const { status, message } = req.body;
    const staffEmail = req.decoded_email;
    const issue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    if (!issue) return res.status(404).send({ message: "Issue not found" });
    await issuesCollection.updateOne(
      { _id: new ObjectId(issueId) },
      { $set: { status }, $push: { timeline: { status, message, updatedBy: staffEmail, role: "Staff", date: new Date() } } }
    );
    const updatedIssue = await issuesCollection.findOne({ _id: new ObjectId(issueId) });
    res.send(updatedIssue);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/staff/:email", verifyFbToken, async (req, res) => {
  try {
    const staffEmail = req.params.email;
    if (req.decoded_email !== staffEmail) return res.status(403).send({ message: "Forbidden" });
    const issues = await issuesCollection.find({ "assignedTo.email": staffEmail }).toArray();
    const stats = { totalAssigned: issues.length, pending: 0, inProgress: 0, working: 0, resolved: 0, todayTasks: 0 };
    const today = new Date().toDateString();
    issues.forEach((issue) => {
      if (issue.status === "Pending") stats.pending++;
      if (issue.status === "In-Progress") stats.inProgress++;
      if (issue.status === "Working") stats.working++;
      if (issue.status === "Resolved") stats.resolved++;
      if (new Date(issue.createdAt).toDateString() === today) stats.todayTasks++;
    });
    res.send(stats);
  } catch (err) {
    res.status(500).send({ message: "Server error" });
  }
});

app.get("/staff/issues/:email", verifyFbToken, verifyStaff, async (req, res) => {
  try {
    const staffEmail = req.params.email;
    if (staffEmail !== req.decoded_email) return res.status(403).send({ message: "Forbidden" });
    const staff = await staffCollection.findOne({ email: staffEmail });
    if (!staff) return res.status(404).send({ message: "Staff not found" });
    const staffDistrict = staff.district;
    const issues = await issuesCollection
      .find({ $or: [{ "assignedTo.email": staffEmail }, { reporterDistrict: staffDistrict, status: "Pending" }] })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(issues);
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

app.get("/staff/issues", verifyFbToken, async (req, res) => {
  const { status, priority } = req.query;
  const query = { "assignedStaff.email": req.decoded_email };
  if (status) query.status = status;
  if (priority) query.priority = priority;
  const issues = await issuesCollection.find(query).sort({ isBoosted: -1, createdAt: -1 }).toArray();
  res.send(issues);
});

// ------------------------
// DASHBOARD - STAFF
// ------------------------
app.get("/dashboard/staff", verifyFbToken, async (req, res) => {
  try {
    const email = req.decoded_email;
    const assignedIssues = await issuesCollection.countDocuments({ "assignedStaff.email": email });
    const resolvedIssues = await issuesCollection.countDocuments({ "assignedStaff.email": email, status: "Resolved" });
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todaysTasks = await issuesCollection.countDocuments({ "assignedStaff.email": email, createdAt: { $gte: today } });
    res.send({ assignedIssues, resolvedIssues, todaysTasks });
  } catch (err) {
    res.status(500).send({ message: "Staff dashboard failed" });
  }
});

app.get("/dashboard/staff/:email", verifyFbToken, verifyStaff, async (req, res) => {
  try {
    const email = req.params.email;
    if (email !== req.decoded_email) return res.status(403).send({ message: "Forbidden" });
    const assignedIssues = await issuesCollection.countDocuments({ assignedTo: email });
    const resolvedIssues = await issuesCollection.countDocuments({ assignedTo: email, status: "Resolved" });
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayTasks = await issuesCollection.countDocuments({ assignedTo: email, updatedAt: { $gte: today } });
    res.send({ assignedIssues, resolvedIssues, todayTasks });
  } catch (err) {
    res.status(500).send({ message: "Internal server error" });
  }
});

// =========================
//  START SERVER (local only)
// =========================
if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

module.exports = app;