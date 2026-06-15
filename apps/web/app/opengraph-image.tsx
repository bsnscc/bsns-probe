import { ImageResponse } from "next/og";

export const alt = "bsns probe";
export const size = {
  width: 1200,
  height: 630
};
export const contentType = "image/png";

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          alignItems: "stretch",
          background: "#f8f8f8",
          color: "#111111",
          display: "flex",
          flexDirection: "column",
          height: "100%",
          justifyContent: "space-between",
          padding: "72px",
          width: "100%"
        }}
      >
        <div style={{ alignItems: "center", display: "flex", gap: "24px" }}>
          <div
            style={{
              background: "#111111",
              borderRadius: "28px",
              display: "flex",
              height: "104px",
              position: "relative",
              width: "104px"
            }}
          >
            <div
              style={{
                background: "#00b88a",
                borderRadius: "999px",
                bottom: "20px",
                height: "24px",
                position: "absolute",
                right: "20px",
                width: "24px"
              }}
            />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            <div style={{ fontSize: 46, fontWeight: 600 }}>bsns tools</div>
            <div style={{ color: "#6b6b6b", fontSize: 28 }}>tools.bsns.cc</div>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
          <div style={{ fontSize: 82, fontWeight: 600, letterSpacing: "-2px", lineHeight: 1 }}>
            Check your domain health.
          </div>
          <div style={{ color: "#6b6b6b", fontSize: 34, lineHeight: 1.35, maxWidth: "920px" }}>
            DNS, website reachability, TLS certificates, HTTP headers, and email authentication.
          </div>
        </div>

        <div
          style={{
            borderTop: "2px solid #e0e0e0",
            color: "#6b6b6b",
            display: "flex",
            fontSize: 26,
            justifyContent: "space-between",
            paddingTop: "28px"
          }}
        >
          <span>Free, open source, no account.</span>
          <span>Built by bsns.cc</span>
        </div>
      </div>
    ),
    size
  );
}
