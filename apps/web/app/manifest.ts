import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "bsns probe",
    short_name: "probe",
    description: "Check a domain's DNS, website, TLS, headers, and email setup.",
    start_url: "/",
    display: "standalone",
    background_color: "#f8f8f8",
    theme_color: "#111111",
    icons: [
      {
        src: "/icon.svg",
        sizes: "any",
        type: "image/svg+xml"
      }
    ]
  };
}
