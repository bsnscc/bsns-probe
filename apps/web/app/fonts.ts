import localFont from "next/font/local";

export const satoshi = localFont({
  variable: "--font-satoshi",
  display: "swap",
  src: [
    { path: "./fonts/satoshi/Satoshi-Regular.woff2", weight: "400", style: "normal" },
    { path: "./fonts/satoshi/Satoshi-Italic.woff2", weight: "400", style: "italic" },
    { path: "./fonts/satoshi/Satoshi-Medium.woff2", weight: "500", style: "normal" },
    { path: "./fonts/satoshi/Satoshi-MediumItalic.woff2", weight: "500", style: "italic" }
  ]
});
