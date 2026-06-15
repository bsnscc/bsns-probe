import { handleScanRequest } from "@/lib/scan-api";

export const runtime = "nodejs";
export const maxDuration = 20;

export const POST = handleScanRequest;
