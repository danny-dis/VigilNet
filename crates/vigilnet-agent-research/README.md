# VigilNet Agent Research

Multi-perspective research and analysis for VigilNet agents.

## Overview

`vigilnet-agent-research` enables collaborative multi-agent research:

- **Perspective Routing**: Distribute queries to specialized agents
- **Sub-Agent System**: Spawn task-specific agents
- **Consensus Building**: Aggregate findings from multiple sources
- **Research Workflows**: Structured analysis pipelines

## Quick Start

```rust
use vigilnet_agent_research::{ResearchCoordinator, Perspective};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let coordinator = ResearchCoordinator::new();
    
    // Research from multiple perspectives
    let perspectives = vec![
        Perspective::Finance,
        Perspective::Technology,
        Perspective::Legal,
    ];
    
    let results = coordinator
        .research("blockchain regulation", perspectives)
        .await?;
    
    for (perspective, analysis) in results {
        println!("{}: {}", perspective, analysis.summary);
    }
    
    Ok(())
}
```

## Perspectives

Built-in perspective types:

```rust
use vigilnet_agent_research::Perspective;

let perspectives = vec![
    Perspective::Finance,      // Financial analysis
    Perspective::Technology,   // Technical feasibility
    Perspective::Legal,        // Regulatory compliance
    Perspective::Security,     // Threat assessment
    Perspective::Ethical,      // Ethical considerations
    Perspective::Market,       // Market analysis
];
```

## Research Coordinator

### Basic Research

```rust
use vigilnet_agent_research::ResearchCoordinator;

let coordinator = ResearchCoordinator::new();

let result = coordinator
    .research("AI in healthcare", vec![Perspective::Technology, Perspective::Legal])
    .await?;
```

### Custom Perspectives

```rust
let custom = Perspective::Custom {
    name: "Environmental".to_string(),
    expertise: vec!["sustainability".to_string(), "carbon-footprint".to_string()],
};
```

## Sub-Agents

Spawn specialized agents for research tasks:

```rust
use vigilnet_agent_research::SubAgent;

let sub_agent = SubAgent::spawn(
    "financial-analyst",
    vec!["finance".to_string(), "accounting".to_string()],
).await?;

let analysis = sub_agent.analyze(query).await?;
```

## Consensus Building

Aggregate findings from multiple agents:

```rust
use vigilnet_agent_research::ConsensusBuilder;

let builder = ConsensusBuilder::new();

for (agent_id, finding) in findings {
    builder.add_finding(agent_id, finding);
}

let consensus = builder.build().await?;
println!("Consensus confidence: {}", consensus.confidence);
```

## Research Workflows

Define structured analysis pipelines:

```rust
use vigilnet_agent_research::{ResearchWorkflow, WorkflowStep};

let workflow = ResearchWorkflow::new()
    .add_step(WorkflowStep::GatherData)
    .add_step(WorkflowStep::Analyze(Perspective::Finance))
    .add_step(WorkflowStep::Analyze(Perspective::Legal))
    .add_step(WorkflowStep::Synthesize)
    .add_step(WorkflowStep::Verify);

let result = workflow.execute("query").await?;
```

## Perspective Router

Route queries to appropriate agents:

```rust
use vigilnet_agent_research::PerspectiveRouter;

let router = PerspectiveRouter::new();

// Register agents with capabilities
router.register(agent_id, vec!["finance".to_string(), "crypto".to_string()]);

// Route based on query
let target_agents = router.route("cryptocurrency investment");
```

## Configuration

```rust
use vigilnet_agent_research::ResearchConfig;

let config = ResearchConfig {
    max_sub_agents: 10,
    consensus_threshold: 0.7,
    timeout_seconds: 300,
    enable_verification: true,
};
```

## Use Cases

- **Investment Research**: Multi-factor analysis
- **Due Diligence**: Comprehensive investigation
- **Policy Analysis**: Multi-stakeholder input
- **Security Audits**: Multi-perspective threat modeling
- **Product Research**: Market/technical/legal analysis

## Integration

- `vigilnet-agent-core`: Agent management
- `vigilnet-agent-circles`: Group collaboration
- `vigilnet-crypto`: Secure communication

## License

GPL-3.0
