//login form stuff
if (localStorage.getItem("neo4jpass") != null) {
    document.getElementById("password").value = localStorage.getItem("neo4jpass");
}

// autoupdate checkbox
autoUpdate = document.getElementById("autoupdate").checked;
document.getElementById("autoupdate").onchange = (e) => {
    autoUpdate = e.target.checked;
}

document.getElementById("loginform").onsubmit = (e) => {
    e.preventDefault()
    const password = document.getElementById("password").value;

    if (neo4jdriver === null) {
        connectNeo4J(password)
            .then((driver) => {
                localStorage.setItem("neo4jpass", password);
                initGraph();
            })
            .catch((error) => {
                loginfeedback.innerText = error;
            });
    } else {
        refreshData();
    }
}

async function initGraph() {
    await addScript("https://unpkg.com/d3-force");
    await addScript("https://unpkg.com/force-graph");

    let graphElement = document.getElementById("graph");
    let GraphObj = ForceGraph()(graphElement);
    graphElement.graphObj = GraphObj;
    // handle resize
    window.addEventListener('resize', () => {
        GraphObj.width(graphElement.offsetWidth).height(graphElement.offsetHeight);
    });

    const NODE_R = 4;
    const COLORS = {
        "MERGE (initial_related1)-[:PURPLE]->(initial_related2)": "purple",
        "MERGE (initial)-[:BLUE]->(related_node)": "blue",
        "CREATE (initial)-[:BLUE]->(related_node)": "blue",
        "MERGE (initial_related)-[:YELLOW]->(redirect_related)": "yellow",
        "CREATE (initial_related)-[:YELLOW]->(redirect_related)": "yellow",
        "SET r.processed = true": "lightgreen",
        "SHOW TRANSACTIONS": "lightgray",
    };
    GraphObj
        .nodeId('transactionId')
        .linkSource('source')
        .linkTarget('target')
        .linkColor("red")
        .linkDirectionalArrowLength(10)
        .nodeColor((n) => {
            let q = n.currentQuery;
            if (q == "") {
                return "gray";
            }
            for (let [pattern, color] of Object.entries(COLORS)) {
                if (q.includes(pattern)) {
                    return color;
                }
            }
            return "black";
        })
        .nodeVal((n) =>
            Math.max(1, Math.min(10, n.status == "Running" ? n.parsedWorkTime : n.parsedWaitTime))
        )
        .nodeLabel((n) => {
            let params_str = "";
            if (n.parameters) {
                params_str += ``;
                for (let [key, value] of Object.entries(n.parameters)) {
                    // if value is string
                    if (typeof value === 'string' || value instanceof String) {
                        value = `"${value}"`;
                    } else if (value instanceof Array) {
                        value = `[${value.length}]`;
                    } else {
                        value = `/${typeof value}/`;
                    }
                    params_str += `${key}: ${value}<br/>`;
                }
            }
            return `<pre>${n.transactionId}<br/>
Status : ${n.status}<br/>
Waiting: ${n.parsedWaitTime}s
Working: ${n.parsedWorkTime}s
Total  : ${n.parsedElapsedTime}s<br/>
${params_str}<br/>
${n.currentQuery}</pre>`;
        })
        // .linkLabel((l) => {
        //     return `TODO`;
        // })
        .nodeRelSize(NODE_R)
        // .nodeCanvasObjectMode(node => node.status === "Running" ? 'before' : undefined)
        .nodeCanvasObjectMode(node => 'before')
        .nodeCanvasObject((node, ctx) => {
            let color = null;
            if (node.status == "Running") {
                color = 'green';
            }
            if (node.status == "Closing") {
                color = 'black';
            }
            if (color != null) {
                // add ring for running nodes
                ctx.beginPath();
                let val = GraphObj.nodeVal()(node);
                const r = Math.sqrt(Math.max(0, val || 1)) * NODE_R;
                ctx.arc(node.x, node.y, r * 1.3, 0, 2 * Math.PI, false);
                ctx.fillStyle = color;
                ctx.fill();
            }
        })
        .graphData({ nodes: [], links: [] })
        // .onNodeClick((node, event) => {
        //     navigator.clipboard.writeText(node.properties.doc_id);
        // })
        // .onLinkClick((link, event) => {
        //     navigator.clipboard.writeText(`MATCH (a)-[r]->(b) WHERE elementId(r)="${link.elementId}" RETURN a,r,b`);
        // })
        ;

    await refreshData();
}

function parseElapsedTime(elapsedTime) {
    // console.log(elapsedTime);
    if (elapsedTime.seconds.low == -1 && elapsedTime.seconds.high == -1) {
        // console.log("Fixing negative seconds");
        elapsedTime.seconds.low = 0;
        elapsedTime.seconds.high = 0;
    }
    if (
        elapsedTime.days.low != 0 || elapsedTime.days.high != 0 ||
        elapsedTime.months.low != 0 || elapsedTime.months.high != 0 ||
        elapsedTime.nanoseconds.high != 0 ||
        elapsedTime.seconds.high != 0
    ) {
        console.error("Not implemented parsing: ", elapsedTime);
        throw new Error("Not implemented", elapsedTime);
    }
    if (elapsedTime.nanoseconds.low < 0 || elapsedTime.seconds.low < 0) {
        console.error("Negative time: ", elapsedTime);
        throw new Error("Negative time", elapsedTime);
    }
    return elapsedTime.seconds.low + elapsedTime.nanoseconds.low / 1e9;
}


async function doAutoRefresh() {
    if (autoUpdate) {
        await refreshData();
    }
}

async function refreshData() {
    let graphElement = document.getElementById("graph");
    let GraphObj = graphElement.graphObj;

    let session = null;
    try {
        session = neo4jdriver.session();
        let results = await session.run('SHOW TRANSACTIONS YIELD *');
        let newNodes = [];
        let newLinks = [];
        console.log(results);
        for (let record of results.records) {
            let transaction = record.toObject();
            // console.log(record, transaction);
            transaction.parsedElapsedTime = parseElapsedTime(transaction.elapsedTime);
            transaction.parsedWaitTime = parseElapsedTime(transaction.waitTime);
            transaction.parsedWorkTime = transaction.parsedElapsedTime - transaction.parsedWaitTime;
            // create copy of record
            newNodes.push(transaction);

            if (transaction.status.startsWith("Blocked by: ")) {
                // "Blocked by [transactionId, transactionId, ...]"
                let blockedBy = transaction.status.slice("Blocked by: [".length, -1).split(", ");
                // console.log(transaction.status, transaction.transactionId, blockedBy);
                for (let blocker of blockedBy) {
                    newLinks.push({
                        source: transaction.transactionId,
                        target: blocker,
                    });
                }
            }
        }

        // GraphObj.graphData({ nodes: newNodes, links: newLinks });

        let { nodes: oldNodes, links: oldLinks } = GraphObj.graphData();

        // merge nodes
        let newNodeIds = new Set(newNodes.map(n => n.transactionId));
        let oldNodeIds = new Set(oldNodes.map(n => n.transactionId));
        // remove nodes that are not in the new data
        for (let node of oldNodes) {
            if (!newNodeIds.has(node.transactionId)) {
                oldNodes.splice(oldNodes.indexOf(node), 1);
            }
        }
        // update existing nodes
        for (let node of newNodes) {
            if (oldNodeIds.has(node.transactionId)) {
                let oldNode = oldNodes.find(n => n.transactionId === node.transactionId);
                Object.assign(oldNode, node);
            }
        }
        // add new nodes
        for (let node of newNodes) {
            if (!oldNodeIds.has(node.transactionId)) {
                oldNodes.push(node);
            }
        }
        GraphObj.graphData({ nodes: oldNodes, links: newLinks });


        // // remove nodes and links that are not in the new data
        // let newNodeIds = new Set(newNodes.map(n => n.transactionId));
        // for (let node of nodes) {
        //     if (!newNodeIds.has(node.transactionId)) {
        //         nodes.splice(nodes.indexOf(node), 1);
        //     }
        // }
        // let newLinkIds = new Set(newLinks.map(l => `${l.source}-${l.target}`));
        // for (let link of links) {
        //     if (!newLinkIds.has(`${link.source}-${link.target}`)) {
        //         links.splice(links.indexOf(link), 1);
        //     }
        // }
        // // add new nodes and links
        // let currentNodeIds = new Set(nodes.map(n => n.transactionId));
        // for (let node of newNodes) {
        //     if (!currentNodeIds.has(node.transactionId)) {
        //         nodes.push(node);
        //     }
        // }
        // let currentLinkIds = new Set(links.map(l => `${l.source}-${l.target}`));
        // for (let link of newLinks) {
        //     if (!currentLinkIds.has(`${link.source}-${link.target}`)) {
        //         links.push(link);
        //     }
        // }
        // GraphObj.graphData({ nodes, links });
    } finally {
        if (session != null) {
            session.close();
        }
    }

    if (autoUpdate) {
        setTimeout(doAutoRefresh, 100);
    }
}