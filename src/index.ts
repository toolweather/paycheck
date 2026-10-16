import type { Env } from "./env";
import { createApp } from "./http";
import { withSources } from "./sources";

const app = createApp();

const PC_REST: [RegExp, string][] = [
  [/^POST \/v1\/check$/, "check_merchant"],
  [/^GET \/v1\/quota$/, "get_quota"],
];

const handler = withSources((request: Request, env: Env, ctx: ExecutionContext) => app.fetch(request, env, ctx), PC_REST);

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Response | Promise<Response> {
    return handler(request, env, ctx);
  },
};
