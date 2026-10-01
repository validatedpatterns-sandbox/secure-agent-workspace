// SAW harness sample tool: plain ESM, no dependencies. The parameters are a
// JSON Schema object (what typebox would generate), so nothing is imported.
const plugin = {
  id: "saw-echo",
  register(api) {
    api.registerTool({
      name: "saw_echo",
      description: "Echo a message back. Proves a harness-delivered .mjs tool loads in the sandbox.",
      parameters: {
        type: "object",
        properties: { message: { type: "string", description: "Text to echo" } },
        required: ["message"],
        additionalProperties: false,
      },
      async execute(_toolCallId, params) {
        const text = `saw-echo: ${params.message}`;
        return { content: [{ type: "text", text }], details: { message: params.message } };
      },
    });
  },
};

export default plugin;
