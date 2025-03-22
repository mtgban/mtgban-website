import type { NextApiRequest, NextApiResponse } from "next"

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const { q, p = "1", sort = "", reverse = "false" } = req.query

    if (!q) {
      return res.status(400).json({ error: "Search query is required" })
    }

    // Format the query according to the specified format
    const formattedQuery = String(q)
    const page = Number(p)
    const isReverse = reverse === "true"

    // In a real implementation, you would call your backend API
    // For now, we'll simulate a response

    // Simulate API call delay
    await new Promise((resolve) => setTimeout(resolve, 500))

    // Return mock data
    return res.status(200).json({
      results: [],
      totalResults: 0,
      page,
      totalPages: 0,
      query: formattedQuery,
      sort: sort || "chrono",
      reverse: isReverse,
    })
  } catch (error) {
    console.error("Search API error:", error)
    return res.status(500).json({ error: "An error occurred while processing your request" })
  }
}

