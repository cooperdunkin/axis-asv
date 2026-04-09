/**
 * services.ts
 *
 * Shared service-action map used by both the MCP server and the public SDK.
 * Maps each supported service to its available actions.
 */

export const SERVICE_ACTIONS: Record<string, string[]> = {
  openai: ["responses.create"],
  anthropic: ["messages.create"],
  github: ["repos.get", "issues.create", "pulls.create", "contents.read"],
  stripe: ["paymentIntents.create", "customers.list"],
  slack: ["chat.postMessage", "conversations.list"],
  sendgrid: ["mail.send"],
  notion: ["pages.create", "databases.query"],
  linear: ["issues.create"],
  twilio: ["messages.create"],
  aws: ["s3.getObject", "s3.putObject"],
  gcp: ["storage.getObject", "storage.listObjects"],
};
