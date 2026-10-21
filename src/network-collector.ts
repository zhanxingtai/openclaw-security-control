import type { EventCollector, ILayerCollector, NetworkLayerConfig, SecurityEvent } from "./types.js";

/**
 * Network layer collector.
 *
 * Reserved for future LLM API Gateway / MCP / DNS / Flow collection;
 * currently logs warnings only when individual sub-collectors are enabled.
 */
export class NetworkCollector implements ILayerCollector {
  readonly name = 'network-collector';
  private collector: EventCollector;
  private config: NetworkLayerConfig;
  private started = false;

  constructor(collector: EventCollector, config: NetworkLayerConfig) {
    this.collector = collector;
    this.config = config;
  }

  async initialize(): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    if (this.config.llmGateway?.enabled) {
      await this.setupLLMGateway();
    }

    if (this.config.mcpMiddleware?.enabled) {
      await this.setupMCPMiddleware();
    }

    if (this.config.dnsLogs?.enabled) {
      await this.setupDNSLogCollector();
    }

    if (this.config.flowLogs?.enabled) {
      await this.setupFlowLogCollector();
    }

    this.started = true;
  }

  async report(event: SecurityEvent): Promise<void> {
    if (!this.config.enabled) {
      return;
    }
    await this.collector.report(event);
  }

  async shutdown(): Promise<void> {
    if (!this.started) {
      return;
    }
    // Reserved: teardown gateway server, close log tail streams, etc.
    this.started = false;
  }

  getStats(): Record<string, unknown> {
    return {
      started: this.started,
      llmGatewayEnabled: this.config.llmGateway?.enabled,
      mcpMiddlewareEnabled: this.config.mcpMiddleware?.enabled,
      dnsLogsEnabled: this.config.dnsLogs?.enabled,
      flowLogsEnabled: this.config.flowLogs?.enabled,
    };
  }

  // ---------------------------------------------------------------------------
  // Reserved extension points
  // ---------------------------------------------------------------------------

  private async setupLLMGateway(): Promise<void> {
    console.warn(
      `[NetworkCollector] LLM Gateway collection is not implemented. ` +
        `Config: port=${this.config.llmGateway?.listenPort}, ` +
        `providers=${JSON.stringify(this.config.llmGateway?.upstreamProviders)}`
    );
  }

  private async setupMCPMiddleware(): Promise<void> {
    console.warn(
      `[NetworkCollector] MCP Middleware collection is not implemented. ` +
        `Servers: ${JSON.stringify(this.config.mcpMiddleware?.monitoredServers)}`
    );
  }

  private async setupDNSLogCollector(): Promise<void> {
    console.warn(
      `[NetworkCollector] DNS log collector is not implemented. ` +
        `Source: ${this.config.dnsLogs?.source}`
    );
  }

  private async setupFlowLogCollector(): Promise<void> {
    console.warn(
      `[NetworkCollector] Flow log collector is not implemented. ` +
        `Provider: ${this.config.flowLogs?.provider}`
    );
  }
}
