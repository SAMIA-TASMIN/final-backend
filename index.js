//  BACKEND SERVER

const { getAuth } = require("firebase-admin/auth");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();

// Stripe secret key from .env
const stripe = require("stripe")(process.env.STRIPE_SECRET);

const app = express();
const port = process.env.PORT || 3000;

// =========================
//  FIREBASE ADMIN INIT
// =========================

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

console.log("Firebase Admin Initialized");

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
//  VERIFY FIREBASE TOKEN MIDDLEWARE
// =========================

const verifyFbToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    console.log(" Missing Authorization header");
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
//  MONGODB INIT
// =========================
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.at3dlqg.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// =========================
//  MAIN (connect DB and register routes)
// =========================
async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    // ------------------------
    // Collections
    // ------------------------
    const db = client.db("public_Infrastructure_user");
    const usersCollection = db.collection("users");
    const issuesCollection = db.collection("issues");
    const paymentsCollection = db.collection("payments");
    const staffCollection = db.collection("staff");

    async function verifyAdmin(req, res, next) {
      try {
        if (!req.decoded_email) {
          return res.status(401).send({ message: "Unauthorized" });
        }
        const adminUser = await usersCollection.findOne({
          email: req.decoded_email,
        });
        if (!adminUser || adminUser.role !== "admin") {
          return res.status(403).send({ message: "Forbidden: admin only" });
        }
        next();
      } catch (err) {
        console.error("verifyAdmin error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    }
    async function verifyStaff(req, res, next) {
      try {
        if (!req.decoded_email) {
          return res.status(401).send({ message: "Unauthorized" });
        }
        const staffUser = await usersCollection.findOne({
          email: req.decoded_email,
        });
        if (!staffUser || staffUser.role !== "staff") {
          return res.status(403).send({ message: "Forbidden: staff only" });
        }
        next();
      } catch (err) {
        console.error("verifyStaff error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    }

    async function addTimelineEntry(issueId, entry) {
      // entry: { status, message, updatedBy, role }
      if (!ObjectId.isValid(issueId)) throw new Error("Invalid issueId");
      const timelineItem = {
        status: entry.status || null,
        message: entry.message || "",
        updatedBy: entry.updatedBy || "System",
        role: entry.role || "System", // "Admin" | "Staff" | "Citizen" | "System"
        date: new Date(),
      };

      return issuesCollection.updateOne(
        { _id: new ObjectId(issueId) },
        { $push: { timeline: timelineItem } }
      );
    }

    // ------------------------
    // ROUTES
    // ------------------------
    // token api
    app.post("/set-token", async (req, res) => {
      try {
        const authHeader = req.headers.authorization;

        if (!authHeader) return res.status(401).send("Missing Authorization");

        const token = authHeader.split(" ")[1];

        if (!token) return res.status(401).send("Invalid token");

        res.cookie("fbToken", token, {
          httpOnly: true,
          secure: false, // true in production
          sameSite: "lax",
          maxAge: 1000 * 60 * 60 * 24,
        });

        res.send({ message: "Token cookie set" });
      } catch (err) {
        res.status(500).send("Failed to set cookie");
      }
    });

    // BASE health check
    app.get("/", (req, res) => {
      res.send("Backend is running successfully!");
    });

    // ------------------------
    // GET USERS (protected) - returns up to 5 users, optional search
    // ------------------------
    app.get("/users", verifyFbToken, async (req, res) => {
      console.log("decoded email", req.decoded_email);
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
        console.error("GET /users error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.get("/users/:email/role", verifyFbToken, async (req, res) => {
      try {
        const email = req.params.email;
        console.log("Param email:", email);
        console.log("Decoded email:", req.decoded_email);

        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });

        res.send({ role: user.role || "citizen" });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // Update user role
    app.patch("/users/:email/role", verifyFbToken, async (req, res) => {
      try {
        const { role } = req.body;
        const email = req.params.email;

        if (!["citizen", "staff", "admin"].includes(role)) {
          return res.status(400).send({ message: "Invalid role" });
        }

        const result = await usersCollection.updateOne(
          { email },
          { $set: { role } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send({ message: "User role updated" });
      } catch (err) {
        console.error("PATCH /users/:email/role error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // ------------------------
    // CREATE USER (unprotected)
    // ------------------------
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

        res.status(201).send({
          message: "User created successfully",
          insertedId: result.insertedId,
        });
      } catch (e) {
        console.error("POST /users error:", e);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    //===================
    // DashBoars related api
    //========================
    // GET /dashboard/citizen/:email
    app.get("/dashboard/citizen/:email", verifyFbToken, async (req, res) => {
      try {
        const email = req.params.email; // use params, not body

        const totalIssues = await issuesCollection.countDocuments({
          userEmail: email,
        });
        const pending = await issuesCollection.countDocuments({
          userEmail: email,
          status: "Pending",
        });
        const inProgress = await issuesCollection.countDocuments({
          userEmail: email,
          status: "In-Progress",
        });
        const resolved = await issuesCollection.countDocuments({
          userEmail: email,
          status: "Resolved",
        });

        const totalPayments = await paymentsCollection
          .aggregate([
            { $match: { email } },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ])
          .toArray();

        res.send({
          totalIssues,
          pending,
          inProgress,
          resolved,
          totalPayments: totalPayments[0]?.total || 0,
        });
      } catch (err) {
        console.error("GET /dashboard/citizen/:email error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // =========================
    // Get logged-in user's profile
    // =========================

    app.get("/profile", verifyFbToken, async (req, res) => {
      try {
        const email = req.query.email || "testuser@example.com";

        // Make query case-insensitive
        let user = await usersCollection.findOne({
          email: { $regex: `^${email}$`, $options: "i" },
        });

        if (!user) {
          console.warn(
            "User not found, creating a test user for email:",
            email
          );

          // Insert a new test user
          const newUser = {
            email,
            displayName: email.split("@")[0], // simple default display name
            photoURL:
              "https://i.pravatar.cc/150?u=" + encodeURIComponent(email),
            isPremium: false,
            isBlocked: false,
          };

          const result = await usersCollection.insertOne(newUser);
          user = newUser;
        } else {
          console.log("User found:", user);
        }

        res.send(user);
      } catch (err) {
        console.error("GET /profile error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // =========================
    // Update logged-in user's profile (name, other info)
    // =========================
    app.patch("/profile", verifyFbToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const updates = req.body;

        if (!email) {
          return res.status(400).send({ message: "Email missing" });
        }

        const result = await usersCollection.updateOne(
          { email },
          { $set: updates }
        );

        if (result.modifiedCount === 0) {
          return res.status(400).send({ message: "Nothing updated" });
        }

        const updatedUser = await usersCollection.findOne({ email });
        res.send(updatedUser);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Internal server error" });
      }
    });
    //==========================
    //admin related api
    //===========================
    app.get("/admin/stats", verifyFbToken, verifyAdmin, async (req, res) => {
      try {
        const totalIssues = await issuesCollection.countDocuments();
        const resolved = await issuesCollection.countDocuments({
          status: "Resolved",
        });
        const pending = await issuesCollection.countDocuments({
          status: "Pending",
        });
        const rejected = await issuesCollection.countDocuments({
          status: "Closed",
        }); // or use a rejected flag
        const paymentsAgg = await paymentsCollection
          .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
          .toArray();
        const totalPayments = paymentsAgg[0]?.total || 0;

        // latest few items
        const latestIssues = await issuesCollection
          .find()
          .sort({ createdAt: -1 })
          .limit(6)
          .toArray();
        const latestPayments = await paymentsCollection
          .find()
          .sort({ createdAt: -1 })
          .limit(6)
          .toArray();
        const latestUsers = await usersCollection
          .find()
          .sort({ createdAt: -1 })
          .limit(6)
          .toArray();

        res.send({
          totalIssues,
          resolved,
          pending,
          rejected,
          totalPayments,
          latestIssues,
          latestPayments,
          latestUsers,
        });
      } catch (err) {
        console.error("GET /admin/stats error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.get("/admin/issues", verifyFbToken, verifyAdmin, async (req, res) => {
      try {
        const page = parseInt(req.query.page || "1", 10);
        const limit = parseInt(req.query.limit || "20", 10);
        const skip = (page - 1) * limit;

        // boosted (priority: "High") first, then others, sort by createdAt desc
        const cursor = issuesCollection
          .find()
          .sort({ priority: 1, createdAt: -1 })
          .skip(skip)
          .limit(limit);
        const issues = await cursor.toArray();
        const total = await issuesCollection.countDocuments();

        res.send({ issues, total, page, limit });
      } catch (err) {
        console.error("GET /admin/issues error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.post(
      "/admin/issues/:id/assign",
      verifyFbToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const issueId = req.params.id;
          const { staffEmail, staffName } = req.body;
          if (!ObjectId.isValid(issueId))
            return res.status(400).send({ message: "Invalid issue id" });
          if (!staffEmail)
            return res.status(400).send({ message: "Missing staffEmail" });

          const issue = await issuesCollection.findOne({
            _id: new ObjectId(issueId),
          });
          if (!issue)
            return res.status(404).send({ message: "Issue not found" });
          if (issue.assignedTo)
            return res.status(400).send({ message: "Already assigned" });

          // update assignedTo only (status moved below)
          await issuesCollection.updateOne(
            { _id: new ObjectId(issueId) },
            {
              $set: {
                assignedTo: { email: staffEmail, name: staffName || null },
                status: "In-Progress",
              },
            }
          );

          // timeline entry — use helper now (no direct $push)
          const timelineItem = {
            status: "In-Progress",
            message: `Issue assigned to Staff: ${staffName || staffEmail}`,
            updatedBy: req.decoded_email,
            role: "Admin",
          };

          await addTimelineEntry(issueId, timelineItem);

          res.send({ message: "Staff assigned" });
        } catch (err) {
          console.error("POST /admin/issues/:id/assign error:", err);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    //===================
    //staff moda related api
    //=======================
    app.delete(
      "/admin/staff/:id",
      verifyFbToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        await staffCollection.deleteOne({ _id: id });
        res.send({ message: "Staff deleted successfully" });
      }
    );

    app.patch(
      "/admin/staff/:id",
      verifyFbToken,
      verifyAdmin,
      async (req, res) => {
        const staffIdString = req.params.id;
        const updateData = req.body;

        delete updateData.email;
        delete updateData.role;
        delete updateData._id;

        try {
          const staffObjectId = new ObjectId(staffIdString);

          const updateDoc = {
            $set: {
              ...updateData,
              updatedAt: new Date(),
            },
          };

          const staffUpdateResult = await staffCollection.updateOne(
            { _id: staffObjectId },
            updateDoc
          );

          const userUpdateResult = await usersCollection.updateOne(
            { _id: staffObjectId },
            updateDoc
          );

          if (
            staffUpdateResult.modifiedCount === 0 &&
            userUpdateResult.modifiedCount === 0
          ) {
            const matched =
              staffUpdateResult.matchedCount > 0 ||
              userUpdateResult.matchedCount > 0;
            if (!matched) {
              return res
                .status(404)
                .send({ message: "Staff member not found in the database." });
            }

            return res.send({
              message: "Staff member found, but no changes were applied.",
            });
          }

          res.send({ message: "Staff updated successfully" });
        } catch (e) {
          console.error("MongoDB update error:", e);

          res.status(500).send({
            message: "Failed to update staff due to a database error.",
          });
        }
      }
    );

    app.get("/admin/staff", verifyFbToken, verifyAdmin, async (req, res) => {
      const staffList = await staffCollection.find().toArray();
      res.send(staffList);
    });

    // --- Add Staff Route ---

    // POST /admin/staff on the backend (Your Node.js file)

    app.post("/admin/staff", verifyFbToken, verifyAdmin, async (req, res) => {
      const { name, email, phone, photo, password, region, district } =
        req.body;

      // ... validation ...

      try {
        // 1. Create user in Firebase Auth (required for login)
        const userRecord = await admin.auth().createUser({
          email,
          password,
          displayName: name,
          photoURL: photo || null,
        });

        const commonUserData = {
          name,
          email,
          phone: phone || "",
          photo: photo || "",
          role: "staff",
          createdAt: new Date(),
        };

        // 2. Insert into USERS Collection
        await usersCollection.insertOne(commonUserData);

        // 3. Insert into STAFF Collection
        const staffSpecific = {
          ...commonUserData, // Re-use common fields
          region,
          district,
          experience: req.body.experience || "0",
          status: req.body.status || "Accepted",
        };
        await staffCollection.insertOne(staffSpecific);

        res.status(201).json({ message: "Staff added successfully" });
      } catch (error) {
        // ... error handling ...
      }
    });
    app.post(
      "/admin/issues/:id/reject",
      verifyFbToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const issueId = req.params.id;
          const { reason } = req.body;
          const issue = await issuesCollection.findOne({
            _id: new ObjectId(issueId),
          });
          if (!issue)
            return res.status(404).send({ message: "Issue not found" });
          if (issue.status !== "Pending")
            return res
              .status(400)
              .send({ message: "Only pending issues can be rejected" });

          await issuesCollection.updateOne(
            { _id: new ObjectId(issueId) },
            { $set: { status: "Closed" } }
          );

          const timelineItem = {
            status: "Closed",
            message: `Issue rejected by admin. Reason: ${
              reason || "Not specified"
            }`,
            updatedBy: req.decoded_email,
            role: "Admin",
          };

          // use helper (removed direct $push)
          await addTimelineEntry(issueId, timelineItem);

          res.send({ message: "Issue rejected" });
        } catch (err) {
          console.error("POST /admin/issues/:id/reject error:", err);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    app.get("/admin/users", verifyFbToken, verifyAdmin, async (req, res) => {
      try {
        const users = await usersCollection
          .find({ role: { $ne: "admin" } })
          .toArray();
        res.send(users);
      } catch (err) {
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.patch(
      "/admin/users/:email/block",
      verifyFbToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const email = req.params.email;
          const { block } = req.body; // { block: true } or false
          const result = await usersCollection.updateOne(
            { email },
            { $set: { isBlocked: !!block } }
          );
          res.send({ modified: result.modifiedCount ? true : false });
        } catch (err) {
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    app.patch(
      "/admin/users/:email/make-admin",
      verifyFbToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const email = req.params.email;

          const result = await usersCollection.updateOne(
            { email },
            { $set: { role: "admin" } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "User not found" });
          }

          res.send({ message: "User promoted to admin" });
        } catch (error) {
          console.error("MAKE ADMIN error:", error);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    // app.post("/subscribe", verifyFbToken, async (req, res) => {

    //   const email = req.decoded_email;
    //   console.log("subscribe email", req.decoded_email);

    //   if (!email) {
    //     return res.status(400).send({ message: "Email missing" });
    //   }

    //   const user = await usersCollection.findOne({ email });
    //   if (!user) return res.status(404).send({ message: "User not found" });

    //   const session = await stripe.checkout.sessions.create({
    //     payment_method_types: ["card"],
    //     mode: "payment",
    //     line_items: [
    //       {
    //         price_data: {
    //           currency: "usd",
    //           unit_amount: 1000, // $10
    //           product_data: { name: "Premium Subscription" },
    //         },
    //         quantity: 1,
    //       },
    //     ],
    //     customer_email: email,
    //     success_url: `${process.env.SITE_DOMAIN}/subscribe-success?session_id={CHECKOUT_SESSION_ID}`,
    //     cancel_url: `${process.env.SITE_DOMAIN}/profile`,
    //   });

    //   res.send({ url: session.url });
    // });

    //-----------------------------------
    // Subscription APIs
    //-----------------------------------

    // Subscribe Success

    app.post("/subscribe", verifyFbToken, async (req, res) => {
      const email = req.decoded_email;
      console.log("Decoded email:", email);

      if (!email) {
        return res.status(400).send({ message: "Email missing" });
      }

      const user = await usersCollection.findOne({ email });

      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      try {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          mode: "payment",
          line_items: [
            {
              price_data: {
                currency: "usd",
                unit_amount: 1000,
                product_data: { name: "Premium Subscription" },
              },
              quantity: 1,
            },
          ],
          customer_email: email,
          success_url: `${process.env.SITE_DOMAIN}/subscribe-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.SITE_DOMAIN}/profile`,
        });

        return res.send({ url: session.url });
      } catch (err) {
        console.log("❌ Stripe Error:", err);
        return res
          .status(500)
          .send({ message: "Stripe Error", error: err.message });
      }
    });

    app.get("/subscribe-success", async (req, res) => {
      try {
        const sessionId = req.query.session_id;

        if (!sessionId)
          return res.status(400).send({ message: "Missing session_id" });

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        const email = session.customer_email;

        if (!email)
          return res.status(400).send({ message: "Customer email missing" });

        await usersCollection.updateOne(
          { email },
          {
            $set: {
              isPremium: true,
              subscriptionDate: new Date(),
            },
          }
        );

        // Save payment history
        await paymentsCollection.insertOne({
          email,
          amount: session.amount_total / 100,
          currency: session.currency,
          createdAt: new Date(),
          sessionId,
        });

        res.send({
          message: "Subscription successful",
          email,
          isPremium: true,
        });
      } catch (err) {
        console.error("GET /subscribe-success error:", err);
        res.status(500).send({
          message: "Subscription success failed",
          error: err.message,
        });
      }
    });

    // ------------------------

    app.post("/issues", verifyFbToken, async (req, res) => {
      try {
        const {
          title,
          description,
          category,
          image,
          reporterRegion,
          reporterDistrict,
        } = req.body;

        // ✅ Validate required fields
        if (
          !title ||
          !description ||
          !category ||
          !reporterRegion ||
          !reporterDistrict
        ) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        // Build issue object
        const issue = {
          title,
          description,
          category,
          image: image || "",
          reporterRegion,
          reporterDistrict,
          userEmail: req.decoded_email,
          createdAt: new Date(),
          status: "Pending",
          priority: "Normal",
          upvotes: 0,
          timeline: [
            {
              status: "Pending",
              message: "Issue reported by citizen",
              updatedBy: req.decoded_email,
              role: "Citizen",
              date: new Date(),
            },
          ],
        };

        const result = await issuesCollection.insertOne(issue);

        res.status(201).send({
          message: "Issue created successfully",
          insertedId: result.insertedId,
        });
      } catch (e) {
        console.error("POST /issues error:", e);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // ------------------------
    // ASSIGN STAFF (protected)
    // ------------------------
    app.post("/issues/:id/assign", async (req, res) => {
      try {
        const issueId = req.params.id;
        const { staffEmail, staffName } = req.body;

        if (!ObjectId.isValid(issueId))
          return res.status(400).send({ message: "Invalid issue id" });
        if (!staffEmail)
          return res.status(400).send({ message: "Missing staff email" });

        // Update assignedTo and status
        await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $set: {
              assignedTo: { email: staffEmail, name: staffName || null },
              status: "In-Progress",
            },
          }
        );

        // Add timeline entry using helper
        await addTimelineEntry(issueId, {
          status: "In-Progress",
          message: `Issue assigned to Staff: ${staffName || staffEmail}`,
          updatedBy: req.decoded_email,
          role: "Admin", // adjust if the caller is staff
        });

        res.send({ message: "Staff assigned and timeline updated" });
      } catch (err) {
        console.error("POST /issues/:id/assign error:", err);
        res
          .status(500)
          .send({ message: "Assignment failed", error: err.message });
      }
    });

    app.get("/issues", async (req, res) => {
      try {
        const { search, status, category, priority, page, limit } = req.query;

        // 1. Pagination Constants
        const pageNumber = parseInt(page) || 1;
        const limitNumber = parseInt(limit) || 9; // Default to 9 items per page
        const skip = (pageNumber - 1) * limitNumber;

        let queryFilter = {};

        // Filtering
        if (status) {
          queryFilter.status = status;
        }
        if (category) {
          queryFilter.category = category;
        }
        if (priority) {
          queryFilter.priority = priority;
        }

        if (search) {
          const searchRegex = new RegExp(search, "i");
          queryFilter.$or = [
            { title: { $regex: searchRegex } },
            { description: { $regex: searchRegex } },
            { reporterDistrict: { $regex: searchRegex } },
            { reporterRegion: { $regex: searchRegex } },
          ];
        }

        const sortOptions = {
          priority: -1,
          createdAt: -1,
        };

        const issues = await issuesCollection
          .find(queryFilter)
          .sort(sortOptions)
          .skip(skip)
          .limit(limitNumber)
          .toArray();

        const totalIssues = await issuesCollection.countDocuments(queryFilter);

        res.send({ issues, totalIssues });
      } catch (e) {
        console.error("GET /issues error:", e);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // ------------------------
    // GET MY ISSUES (public, filters by email param)
    // ------------------------
    app.get("/issues/my-issues", verifyFbToken, async (req, res) => {
      try {
        const email = req.decoded_email; // from token
        const issues = await issuesCollection
          .find({ userEmail: email }) // match exactly with DB
          .sort({ createdAt: -1 })
          .toArray();

        res.status(200).send(issues);
      } catch (err) {
        console.error("GET /issues/my-issues error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // ------------------------
    // GET SINGLE ISSUE (public)
    // ------------------------
    app.get("/issues/:id", async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid issue ID" });
        }

        const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
        if (!issue) return res.status(404).send({ message: "Issue not found" });

        res.send(issue);
      } catch (err) {
        console.error("GET /issues/:id error:", err);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // ------------------------
    // CHANGE STATUS (protected)
    // - body: { status, note }
    // ------------------------

// PATCH /issues/:id — Edit issue (owner only, pending status only)
app.patch("/issues/:id", verifyFbToken, async (req, res) => {
  try {
    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid ID" });
    }

    const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

    if (!issue) {
      return res.status(404).send({ message: "Issue not found" });
    }

    // Only allow owner to edit
    if (issue.userEmail !== req.decoded_email) {
      return res.status(403).send({ message: "Forbidden: only owner can edit this issue" });
    }

    // Only allow editing if status is Pending
    if (issue.status !== "Pending") {
      return res.status(400).send({ message: "Only pending issues can be edited" });
    }

    const { title, description, category, image } = req.body;

    const updateDoc = {
      $set: {
        ...(title && { title }),
        ...(description && { description }),
        ...(category && { category }),
        ...(image && { image }),
        updatedAt: new Date(),
      },
    };

    await issuesCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);

    res.status(200).send({ message: "Issue updated successfully" });
  } catch (err) {
    console.error("PATCH /issues/:id error:", err);
    res.status(500).send({ message: "Internal server error" });
  }
});

    app.post("/issues/:id/status", async (req, res) => {
      try {
        const issueId = req.params.id;
        const { status, note } = req.body;

        const allowed = ["Pending", "In-Progress", "Resolved", "Closed"];
        if (!allowed.includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          { $set: { status } }
        );

        await addTimelineEntry(issueId, {
          status,
          message: note || `Status changed to ${status}`,
          updatedBy: req.decoded_email,
          role: "Staff", // or Admin depending on your role logic
        });

        res.send({ message: "Status updated and timeline entry added" });
      } catch (err) {
        console.error("POST /issues/:id/status error:", err);
        res
          .status(500)
          .send({ message: "Status update failed", error: err.message });
      }
    });

    // ------------------------
    // REJECT/CLOSE ISSUE (protected)
    // ------------------------
    app.post("/issues/:id/reject", async (req, res) => {
      try {
        const issueId = req.params.id;
        const { reason } = req.body;

        await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          { $set: { status: "Closed" } }
        );

        await addTimelineEntry(issueId, {
          status: "Closed",
          message: `Issue rejected by admin. Reason: ${
            reason || "Not specified"
          }`,
          updatedBy: req.decoded_email,
          role: "Admin",
        });

        res.send({ message: "Issue rejected and closed" });
      } catch (err) {
        console.error("POST /issues/:id/reject error:", err);
        res.status(500).send({ message: "Reject failed", error: err.message });
      }
    });

    // ------------------------
    // UPVOTE ISSUE (protected)
    // ------------------------
    app.patch("/issues/upvote/:id", async (req, res) => {
      try {
        const issueId = req.params.id;
        const userEmail = req.decoded_email;

        const issue = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
        });
        if (!issue) {
          return res.status(404).send({ message: "Issue not found" });
        }

        if (issue.userEmail === userEmail) {
          return res
            .status(400)
            .send({ message: "You cannot upvote your own issue" });
        }

        // Check if user already upvoted
        const hasVoted = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
          upvotedUsers: userEmail,
        });

        if (hasVoted) {
          return res
            .status(400)
            .send({ message: "You have already upvoted this issue" });
        }

        // Add upvote
        await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $inc: { upvotes: 1 },
            $push: { upvotedUsers: userEmail },
          }
        );

        // Add a timeline entry for the upvote (optional)
        await addTimelineEntry(issueId, {
          status: issue.status || "Pending",
          message: `Issue upvoted by ${userEmail}`,
          updatedBy: userEmail,
          role: "Citizen",
        });

        res.status(200).send({ message: "Upvoted successfully" });
      } catch (err) {
        console.error("PATCH /issues/upvote/:id error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // ------------------------
    // DELETE ISSUE (protected)
    // ------------------------
    app.delete("/issues/:id", verifyFbToken, async (req, res) => {
      try {
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID" });
        }

        const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });

        if (!issue) {
          return res.status(404).send({ message: "Issue not found" });
        }

        // Only allow owner to delete
        if (issue.userEmail !== req.decoded_email) {
          return res
            .status(403)
            .send({ message: "Forbidden: only owner can delete this issue" });
        }

        await issuesCollection.deleteOne({ _id: new ObjectId(id) });

        res.status(200).send({ message: "Issue deleted successfully" });
      } catch (err) {
        console.error("DELETE /issues/:id error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // ------------------------
    // PAYMENT-RELATED ROUTES
    // ------------------------

    // CREATE BOOST SESSION (protected)
    // Frontend calls this to create a Stripe checkout session.
    app.post("/create-boost-session", verifyFbToken, async (req, res) => {
      try {
        const { issueId, cost, title, userEmail } = req.body;

        if (!issueId || !cost || !title || !userEmail) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        // Ensure email matches authenticated user
        if (userEmail !== req.decoded_email) {
          return res.status(403).json({ message: "Forbidden access" });
        }

        // create stripe session
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "usd",
                unit_amount: parseInt(cost, 10) * 100,
                product_data: {
                  name: `Boost Issue: ${title}`,
                },
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          metadata: {
            issueId,
            title,
          },
          customer_email: userEmail,
          success_url: `${process.env.SITE_DOMAIN}/boost-success?session_id={CHECKOUT_SESSION_ID}&issueId=${issueId}`,
          cancel_url: `${process.env.SITE_DOMAIN}/issue/${issueId}`,
        });

        res.json({ url: session.url });
      } catch (err) {
        console.error("POST /create-boost-session error:", err);
        res
          .status(500)
          .json({ message: "Stripe session failed", error: err.message });
      }
    });

    app.get("/admin/payments", verifyFbToken, verifyAdmin, async (req, res) => {
      try {
        const payments = await paymentsCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();

        res.send(payments);
      } catch (err) {
        console.error("GET /admin/payments error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // BOOST SUCCESS (public)
    //
    app.get("/boost-success", verifyFbToken, async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId)
          return res.status(400).send({ message: "Missing session_id" });

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        // Read metadata + customer email
        const issueId = session.metadata && session.metadata.issueId;
        const title = session.metadata && session.metadata.title;
        const email = session.customer_email;

        if (!issueId)
          return res
            .status(400)
            .send({ message: "Missing issueId in session metadata" });

        // Validate issueId
        if (!ObjectId.isValid(issueId))
          return res.status(400).send({ message: "Invalid issueId" });

        // 1) Update issue priority (no direct timeline push here)
        await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $set: { priority: "High" },
          }
        );

        // 2) Insert payment into payments collection
        await paymentsCollection.insertOne({
          issueId,
          title,
          email,
          amount: session.amount_total ? session.amount_total / 100 : null,
          currency: session.currency || null,
          paymentStatus: session.payment_status || null,
          transactionId: session.id,
          createdAt: new Date(),
        });

        // 3) Append a timeline entry via helper (single source of truth)
        await addTimelineEntry(issueId, {
          status: null,
          message: "Issue boosted by payment",
          updatedBy: email,
          role: "Citizen",
        });

        res.send({
          message: "Payment Success — Issue Boosted",
          issueId,
          email,
          status: "success",
        });
      } catch (err) {
        console.error("GET /boost-success error:", err);
        res
          .status(500)
          .send({ message: "Boost success failed", error: err.message });
      }
    });

    // OPTIONAL: Get payments for a user (protected)
    app.get("/payments", verifyFbToken, async (req, res) => {
      try {
        const email = req.decoded_email;

        const payments = await paymentsCollection
          .find({ email })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(payments);
      } catch (err) {
        console.error("GET /payments error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    //=======================
    //staff related api
    //-----------------------

    // Get all staff applications
    app.get("/staff", verifyFbToken, async (req, res) => {
      try {
        const staffList = await staffCollection.find().toArray();
        res.send(staffList);
      } catch (err) {
        console.error("GET /staff error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // POST /staff-applications

    app.post("/staff", verifyFbToken, async (req, res) => {
      try {
        const staffData = req.body;

        const requiredFields = ["name", "email", "phone", "region", "district"];
        for (const field of requiredFields) {
          if (!staffData[field]) {
            return res.status(400).send({ message: `${field} is required` });
          }
        }

        delete staffData._id;

        if (!staffData.status) {
          staffData.status = "Accepted";
        }
        if (!staffData.experience) {
          staffData.experience = "0";
        }

        staffData.submittedAt = new Date();
        staffData.timeline = [
          {
            status: staffData.status,
            message: "Staff member created by Admin.",
            updatedBy: req.decoded_email,
            role: "Admin",
            date: new Date(),
          },
        ];

        const result = await staffCollection.insertOne(staffData);

        res.status(201).send({
          message: "Staff member added successfully",
          insertedId: result.insertedId,
        });
      } catch (err) {
        console.error("POST /staff error:", err);
        res
          .status(500)
          .send({ message: "Internal server error", error: err.message });
      }
    });

    // Update staff status
    app.patch("/staff/:email", verifyFbToken, async (req, res) => {
      try {
        const { status } = req.body;
        const email = req.params.email;

        if (!["Pending", "Accepted", "Rejected"].includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const result = await staffCollection.updateOne(
          { email },
          { $set: { status } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Staff not found" });
        }

        res.send({ message: "Staff status updated" });
      } catch (err) {
        console.error("PATCH /staff/:email error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // PATCH /staff/issues/:id/status
    app.patch("/staff/issues/:id/status", verifyFbToken, async (req, res) => {
      try {
        const issueId = req.params.id;
        const { status, message } = req.body;
        const staffEmail = req.decoded_email;

        const issue = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
        });

        if (!issue) {
          return res.status(404).send({ message: "Issue not found" });
        }

        const updateDoc = {
          $set: { status },
          $push: {
            timeline: {
              status,
              message,
              updatedBy: staffEmail,
              role: "Staff",
              date: new Date(),
            },
          },
        };

        await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          updateDoc
        );

        const updatedIssue = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
        });

        res.send(updatedIssue);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Internal server error" });
      }
    });
    app.get("/staff/:email", verifyFbToken, async (req, res) => {
      try {
        const staffEmail = req.params.email;

        if (req.decoded_email !== staffEmail) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const issues = await issuesCollection
          .find({
            "assignedTo.email": staffEmail,
          })
          .toArray();

        const stats = {
          totalAssigned: issues.length,
          pending: 0,
          inProgress: 0,
          working: 0,
          resolved: 0,
          todayTasks: 0,
        };

        const today = new Date().toDateString();

        issues.forEach((issue) => {
          if (issue.status === "Pending") stats.pending++;
          if (issue.status === "In-Progress") stats.inProgress++;
          if (issue.status === "Working") stats.working++;
          if (issue.status === "Resolved") stats.resolved++;

          if (new Date(issue.createdAt).toDateString() === today) {
            stats.todayTasks++;
          }
        });

        res.send(stats);
      } catch (err) {
        console.error("Staff dashboard error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // GET /staff/issues/:email
    app.get(
      "/staff/issues/:email",
      verifyFbToken,
      verifyStaff,
      async (req, res) => {
        try {
          const staffEmail = req.params.email;
          if (staffEmail !== req.decoded_email) {
            return res.status(403).send({ message: "Forbidden" });
          }

          // Get the staff document
          const staff = await staffCollection.findOne({ email: staffEmail });
          if (!staff)
            return res.status(404).send({ message: "Staff not found" });

          const staffDistrict = staff.district;

          // Fetch issues:
          // 1️⃣ Already assigned to this staff via issue.assignedTo.email
          // 2️⃣ Pending issues in the same district
          const issues = await issuesCollection
            .find({
              $or: [
                { "assignedTo.email": staffEmail }, // already assigned
                { reporterDistrict: staffDistrict, status: "Pending" }, // pending in same district
              ],
            })
            .sort({ createdAt: -1 })
            .toArray();

          res.send(issues);
        } catch (err) {
          console.error("GET /staff/issues/:email error:", err);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    app.get("/dashboard/staff", verifyFbToken, async (req, res) => {
      try {
        const email = req.decoded_email;

        const assignedIssues = await issuesCollection.countDocuments({
          "assignedStaff.email": email,
        });

        const resolvedIssues = await issuesCollection.countDocuments({
          "assignedStaff.email": email,
          status: "Resolved",
        });

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const todaysTasks = await issuesCollection.countDocuments({
          "assignedStaff.email": email,
          createdAt: { $gte: today },
        });

        res.send({
          assignedIssues,
          resolvedIssues,
          todaysTasks,
        });
      } catch (err) {
        res.status(500).send({ message: "Staff dashboard failed" });
      }
    });

    app.get("/staff/issues", verifyFbToken, async (req, res) => {
      const { status, priority } = req.query;

      const query = {
        "assignedStaff.email": req.decoded_email,
      };

      if (status) query.status = status;
      if (priority) query.priority = priority;

      const issues = await issuesCollection
        .find(query)
        .sort({ isBoosted: -1, createdAt: -1 }) // boosted first
        .toArray();

      res.send(issues);
    });

    app.patch("/issues/:id/status", verifyFbToken, async (req, res) => {
      try {
        const { status } = req.body;
        const issueId = req.params.id;

        const issue = await issuesCollection.findOne({
          _id: new ObjectId(issueId),
        });

        if (!issue) return res.status(404).send({ message: "Issue not found" });

        // Staff ownership check
        if (issue.assignedStaff?.email !== req.decoded_email) {
          return res.status(403).send({ message: "Forbidden" });
        }

        const allowed = {
          Pending: ["In-Progress"],
          "In-Progress": ["Working"],
          Working: ["Resolved"],
          Resolved: ["Closed"],
        };

        if (!allowed[issue.status]?.includes(status)) {
          return res.status(400).send({ message: "Invalid status transition" });
        }

        await issuesCollection.updateOne(
          { _id: new ObjectId(issueId) },
          {
            $set: { status },
            $push: {
              timeline: {
                status,
                message: `Status changed to ${status}`,
                updatedBy: req.decoded_email,
                role: "Staff",
                date: new Date(),
              },
            },
          }
        );

        res.send({ message: "Status updated successfully" });
      } catch (err) {
        res.status(500).send({ message: "Status update failed" });
      }
    });

    app.get(
      "/dashboard/staff/:email",
      verifyFbToken,
      verifyStaff,
      async (req, res) => {
        try {
          const email = req.params.email;

          if (email !== req.decoded_email) {
            return res.status(403).send({ message: "Forbidden" });
          }

          // Assigned issues
          const assignedIssues = await issuesCollection.countDocuments({
            assignedTo: email,
          });

          const resolvedIssues = await issuesCollection.countDocuments({
            assignedTo: email,
            status: "Resolved",
          });

          // Today's tasks
          const today = new Date();
          today.setHours(0, 0, 0, 0);

          const todayTasks = await issuesCollection.countDocuments({
            assignedTo: email,
            updatedAt: { $gte: today },
          });

          res.send({
            assignedIssues,
            resolvedIssues,
            todayTasks,
          });
        } catch (err) {
          console.error("GET /dashboard/staff/:email error:", err);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    // End of route registrations inside run()
  } catch (err) {
    console.error("Main run error:", err);
  }
}

run().catch(console.dir);

// =========================
//  START SERVER
// =========================
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
