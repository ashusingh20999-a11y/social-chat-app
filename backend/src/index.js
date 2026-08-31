export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({
        ok: true,
        service: "social-chat-api"
      });
    }

    return Response.json({
      message: "Social Chat API is running"
    });
  }
};