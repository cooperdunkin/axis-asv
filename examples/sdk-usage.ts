import { AxisVault } from "axis-asv";

const vault = new AxisVault({
  masterPassword: process.env.AXIS_MASTER_PASSWORD!,
  identity: "my-agent",
});

// Store a credential (one-time setup)
await vault.addCredential("openai", process.env.OPENAI_API_KEY!);

// Later: agent calls through Axis (key never exposed)
const result = await vault.executeAction({
  service: "openai",
  action: "responses.create",
  justification: "User asked me to summarize a document",
  params: { model: "gpt-4o", input: "Summarize this..." },
});

console.log(result);
