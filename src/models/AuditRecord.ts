import mongoose, { Schema, Document, Model } from "mongoose";

export interface IAuditRecord extends Document {
  moduleName: string;
  sourceCode?: string;
  loc: number;
  cyclomaticComplexity: number;
  maintainabilityIndex: number;
  technicalDebtHours: string;
  issuesCount: number;
  issues: any[];
  manifestAudits: any[];
  refactoredCode: string;
  createdAt: Date;
}

const AuditRecordSchema = new Schema(
  {
    moduleName: { type: String, required: true },
    sourceCode: { type: String, default: "" },
    loc: { type: Number, required: true },
    cyclomaticComplexity: { type: Number, required: true },
    maintainabilityIndex: { type: Number, required: true },
    technicalDebtHours: { type: String, required: true },
    issuesCount: { type: Number, required: true, default: 0 },
    issues: { type: Array, default: [] },
    manifestAudits: { type: Array, default: [] },
    refactoredCode: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now },
  },
  {
    timestamps: false,
  }
);

const AuditRecord: Model<IAuditRecord> =
  mongoose.models.AuditRecord || mongoose.model<IAuditRecord>("AuditRecord", AuditRecordSchema);

export default AuditRecord;
