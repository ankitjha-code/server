const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const dotenv = require("dotenv");
const {
  Connection,
  PublicKey,
  Transaction,
  SystemProgram,
  Keypair,
  TransactionInstruction,
} = require("@solana/web3.js");
const bs58 = require("bs58");

dotenv.config();

const ADMIN_PUBLIC_KEY = "AH9WTkjGcnUUzrc9L4Ar5BxhxVq96NXXHp2ZkesS61pi";

// Admin middleware
function adminOnly(req, res, next) {
  console.log("Admin middleware check:", req.headers);
  console.log("Expected admin key:", ADMIN_PUBLIC_KEY);
  console.log("Received admin key:", req.headers["x-admin-wallet"]);

  if (req.headers["x-admin-wallet"] !== ADMIN_PUBLIC_KEY) {
    console.log("Admin authorization failed");
    return res
      .status(403)
      .json({ success: false, message: "Unauthorized admin access" });
  }
  console.log("Admin authorization successful");
  next();
}

// Initialize Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "kyc_documents",
    allowed_formats: ["jpg", "png", "pdf"],
  },
});

const upload = multer({ storage: storage });

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Solana connection
const solanaConnection = new Connection(
  process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com",
  "confirmed"
);

// MongoDB connection
mongoose
  .connect(
    process.env.MONGODB_URI || "mongodb://localhost:27017/subsidy_system",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// MongoDB Models
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    walletAddress: { type: String, unique: true },
    kycDocumentUrl: String,
    kycVerified: { type: Boolean, default: false },
    kycVerifiedAt: { type: Date },
    allocatedFunds: { type: Number, default: 0 },
    registeredAt: { type: Date, default: Date.now },
  })
);

const SubsidyRequest = mongoose.model(
  "SubsidyRequest",
  new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    amount: Number,
    reason: String,
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    rejectionReason: String,
    resubmissionNote: String,
    isResubmission: { type: Boolean, default: false },
    originalRequestId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "SubsidyRequest",
    },
    transactionHash: String,
    requestedAt: { type: Date, default: Date.now },
    processedAt: Date,
  })
);

// Add new KYC History model
const KycHistory = mongoose.model(
  "KycHistory",
  new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    submissions: [
      {
        documentUrl: String,
        submittedAt: { type: Date, default: Date.now },
        status: {
          type: String,
          enum: ["pending", "approved", "rejected"],
          default: "pending",
        },
        verifiedAt: Date,
        rejectedAt: Date,
        rejectionReason: String,
        isResubmission: Boolean,
        resubmissionNote: String,
      },
    ],
  })
);

// Utility function to create subsidy instruction
// Updated subsidy instruction function with proper account structure
const createSubsidyInstruction = (
  adminPubkey,
  recipientPubkey,
  amount,
  programId
) => {
  // Simple transfer instruction for direct SOL transfers
  return SystemProgram.transfer({
    fromPubkey: adminPubkey,
    toPubkey: recipientPubkey,
    lamports: amount,
  });
};
// Routes
app.post("/api/users/register", async (req, res) => {
  try {
    const { name, email, walletAddress } = req.body;
    const newUser = new User({
      name,
      email,
      walletAddress,
    });
    await newUser.save();
    res.status(201).json({ success: true, user: newUser });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post(
  "/api/users/upload-kyc/:userId",
  upload.single("document"),
  async (req, res) => {
    try {
      const user = await User.findById(req.params.userId);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      // Save the document URL
      user.kycDocumentUrl = req.file.path;
      await user.save();

      // Create KYC history entry or update existing one
      let kycHistory = await KycHistory.findOne({ userId: user._id });

      if (!kycHistory) {
        kycHistory = new KycHistory({
          userId: user._id,
          submissions: [],
        });
      }

      // Create new submission entry
      const isResubmission = req.body.isResubmission === "true";
      const newSubmission = {
        documentUrl: req.file.path,
        submittedAt: new Date(),
        status: "pending",
        isResubmission: isResubmission,
      };

      // Add resubmission note if provided
      if (isResubmission && req.body.resubmissionNote) {
        newSubmission.resubmissionNote = req.body.resubmissionNote;
      }

      kycHistory.submissions.push(newSubmission);
      await kycHistory.save();

      res.json({ success: true, documentUrl: req.file.path });
    } catch (error) {
      console.error("KYC upload error:", error);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);

// Admin routes - make both versions available
app.put("/api/admin/verify-kyc/:userId", adminOnly, async (req, res) => {
  try {
    const { approved, rejectionReason } = req.body;
    const user = await User.findById(req.params.userId);

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Update user KYC status
    user.kycVerified = approved;
    user.kycVerifiedAt = approved ? new Date() : null;
    await user.save();

    // Update KYC history
    const kycHistory = await KycHistory.findOne({ userId: user._id });

    if (kycHistory && kycHistory.submissions.length > 0) {
      // Update the most recent submission
      const latestSubmission =
        kycHistory.submissions[kycHistory.submissions.length - 1];

      latestSubmission.status = approved ? "approved" : "rejected";

      if (approved) {
        latestSubmission.verifiedAt = new Date();
      } else {
        latestSubmission.rejectedAt = new Date();
        latestSubmission.rejectionReason = rejectionReason;
      }

      await kycHistory.save();
    }

    res.json({
      success: true,
      message: `User KYC ${approved ? "approved" : "rejected"} successfully`,
      user,
    });
  } catch (error) {
    console.error("KYC verification error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post("/api/subsidies/request", async (req, res) => {
  try {
    const { userId, amount, reason } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    if (!user.kycVerified) {
      return res
        .status(403)
        .json({ success: false, message: "KYC not verified" });
    }
    const newRequest = new SubsidyRequest({
      userId,
      amount,
      reason,
    });
    await newRequest.save();
    res.status(201).json({ success: true, request: newRequest });
  } catch (error) {
    console.error("Subsidy request error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Resubmit rejected request
app.post("/api/subsidies/resubmit/:requestId", async (req, res) => {
  try {
    const { userId, resubmissionNote } = req.body;
    const originalRequestId = req.params.requestId;

    // Find the original rejected request
    const originalRequest = await SubsidyRequest.findById(originalRequestId);
    if (!originalRequest) {
      return res
        .status(404)
        .json({ success: false, message: "Original request not found" });
    }

    if (originalRequest.status !== "rejected") {
      return res.status(400).json({
        success: false,
        message: "Only rejected requests can be resubmitted",
      });
    }

    // Create a new request based on the original one
    const newRequest = new SubsidyRequest({
      userId,
      amount: originalRequest.amount,
      reason: originalRequest.reason,
      isResubmission: true,
      originalRequestId,
      resubmissionNote,
    });

    await newRequest.save();
    res.status(201).json({ success: true, request: newRequest });
  } catch (error) {
    console.error("Resubmit subsidy error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Consolidated subsidy processing route with fixed bs58 handling
app.put(
  "/api/admin/process-subsidy/:requestId",
  adminOnly,
  async (req, res) => {
    try {
      const { approved, rejectionReason } = req.body;
      const requestId = req.params.requestId;

      const subsidyRequest = await SubsidyRequest.findById(requestId).populate(
        "userId"
      );
      if (!subsidyRequest) {
        return res
          .status(404)
          .json({ success: false, message: "Request not found" });
      }

      // Set status and processed timestamp
      subsidyRequest.status = approved ? "approved" : "rejected";
      subsidyRequest.processedAt = new Date();

      // Store rejection reason if not approved
      if (!approved && rejectionReason) {
        subsidyRequest.rejectionReason = rejectionReason;
      }

      // If approved, proceed with the SOL payment transaction
      if (approved) {
        try {
          // Get the private key from environment
          const adminPrivateKeyString = process.env.ADMIN_WALLET_PRIVATE_KEY;

          // Fix: Re-require bs58 to ensure we get a fresh instance
          const bs58Lib = require("bs58");
          let adminPrivateKeyBytes;

          // Try different approaches to decode the private key
          if (typeof bs58Lib.decode === "function") {
            adminPrivateKeyBytes = bs58Lib.decode(adminPrivateKeyString);
          } else if (typeof bs58Lib === "function") {
            adminPrivateKeyBytes = bs58Lib(adminPrivateKeyString);
          } else {
            throw new Error("bs58 decode function not available");
          }

          console.log("Decoded key length:", adminPrivateKeyBytes.length);

          const adminKeypair = Keypair.fromSecretKey(adminPrivateKeyBytes);
          console.log("Admin public key:", adminKeypair.publicKey.toString());

          // Create the transaction using standard SOL transfer
          const recipientPubkey = new PublicKey(
            subsidyRequest.userId.walletAddress
          );
          const amountLamports = subsidyRequest.amount * 1e9;

          // Use the SystemProgram.transfer instruction directly
          const transaction = new Transaction().add(
            SystemProgram.transfer({
              fromPubkey: adminKeypair.publicKey,
              toPubkey: recipientPubkey,
              lamports: amountLamports,
            })
          );

          transaction.feePayer = adminKeypair.publicKey;
          const { blockhash } = await solanaConnection.getRecentBlockhash();
          transaction.recentBlockhash = blockhash;
          transaction.sign(adminKeypair);

          // Send and confirm transaction
          const signature = await solanaConnection.sendRawTransaction(
            transaction.serialize()
          );
          await solanaConnection.confirmTransaction(signature);
          subsidyRequest.transactionHash = signature;

          // Update user's allocated funds
          subsidyRequest.userId.allocatedFunds =
            (subsidyRequest.userId.allocatedFunds || 0) + subsidyRequest.amount;
          await subsidyRequest.userId.save();
        } catch (txError) {
          console.error("Transaction processing error:", txError);
          console.error(
            "Transaction logs:",
            txError.transactionLogs || "No logs available"
          );
          return res.status(500).json({
            success: false,
            message: "Failed to process transaction",
            error: txError.message,
          });
        }
      }

      await subsidyRequest.save();
      res.json({ success: true, request: subsidyRequest });
    } catch (error) {
      console.error("Process subsidy error:", error);
      console.error("Error stack:", error.stack);
      res.status(500).json({ success: false, message: error.message });
    }
  }
);
// Get all users for admin with sorting
app.get("/api/admin/users", adminOnly, async (req, res) => {
  try {
    const users = await User.find().sort({ registeredAt: -1 });
    res.json({ success: true, users });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Legacy route without api prefix
app.get("/admin/users", adminOnly, async (req, res) => {
  try {
    const users = await User.find().sort({ registeredAt: -1 });
    res.json({ success: true, users });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get all subsidy requests for admin with improved sorting and population
app.get("/api/admin/subsidy-requests", adminOnly, async (req, res) => {
  try {
    const requests = await SubsidyRequest.find()
      .populate("userId", "name email walletAddress")
      .sort({ requestedAt: -1 });
    res.json({ success: true, requests });
  } catch (error) {
    console.error("Get requests error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Legacy route without api prefix
app.get("/admin/subsidy-requests", adminOnly, async (req, res) => {
  try {
    const requests = await SubsidyRequest.find()
      .populate("userId", "name email walletAddress")
      .sort({ requestedAt: -1 });
    res.json({ success: true, requests });
  } catch (error) {
    console.error("Get requests error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get user by wallet address
app.get("/api/users/wallet/:address", async (req, res) => {
  try {
    const walletAddress = req.params.address;
    const user = await User.findOne({ walletAddress });

    if (user) {
      res.json({ success: true, user });
    } else {
      res.json({ success: false, message: "User not found" });
    }
  } catch (error) {
    console.error("Get wallet user error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get a user's subsidy requests
app.get("/api/subsidies/user/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const requests = await SubsidyRequest.find({ userId }).sort({
      requestedAt: -1,
    });

    res.json({ success: true, requests });
  } catch (error) {
    console.error("Get user subsidy requests error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Add endpoint to get user's KYC history
app.get("/api/users/kyc-history/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;

    let kycHistory = await KycHistory.findOne({ userId });

    if (!kycHistory) {
      kycHistory = {
        userId,
        submissions: [],
      };
    }

    res.json({ success: true, kycHistory });
  } catch (error) {
    console.error("Get KYC history error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
