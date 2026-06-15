import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const updatedAt = new Date("2026-06-15T00:00:00.000Z");

  return [
    {
      url: "https://tools.bsns.cc/",
      lastModified: updatedAt,
      changeFrequency: "weekly",
      priority: 1
    },
    {
      url: "https://tools.bsns.cc/privacy",
      lastModified: updatedAt,
      changeFrequency: "monthly",
      priority: 0.4
    },
    {
      url: "https://tools.bsns.cc/security",
      lastModified: updatedAt,
      changeFrequency: "monthly",
      priority: 0.4
    }
  ];
}
