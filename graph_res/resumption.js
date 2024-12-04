if (localStorage.getItem("neo4jpass") == null) {
    throw new Error("No password stored");
}

const edge_id = new URL(window.location).searchParams.get("edge_id");

function round_similarity(similarity) {
    if (similarity === undefined || similarity === null) {
        return "N/A";
    }
    if (typeof similarity === "number") {
        return similarity.toFixed(2);
    }
    let ret = `${similarity}`;
    while (ret.length < 4) {
        ret = " " + ret;
    }
    return ret;
}

function render_similarities_of_node(node, similarity) {
    let sim_i = "N/A";
    let sim_r = "N/A";
    if (node.link_I) {
        sim_i = round_similarity(node.link_I.properties[similarity]);
    }
    if (node.link_R) {
        sim_r = round_similarity(node.link_R.properties[similarity]);
    }
    return `${sim_i} | ${sim_r}`;
}

async function main() {
    await connectNeo4J(localStorage.getItem("neo4jpass"));

    let session = neo4jdriver.session();
    GraphData = {
        nodes: [],
        links: []
    };
    let graphElement = document.getElementById("graph");
    let similarity_prop = "similarity_levenshtein";
    let prepare_job = prepareGraph(graphElement, similarity_prop)

    let results = await session.run(`MATCH (I) - [IR: SIM { first_color: "WHITE" }] - (R:REDIRECT_HTML)
                WHERE elementId(IR) = $edge_id
                RETURN I, IR, R`, { edge_id: edge_id });

    let record = results.records[0]
    let I = record.get("I");
    let R = record.get("R");
    let IR = record.get("IR");
    I.nodeSize = 4;
    R.nodeSize = 4;
    IR.linkWidth = 4;
    IR.linkDistance = 200;
    if (IR.startNodeElementId == R.elementId && IR.endNodeElementId == I.elementId) {
        // for some reason the direction is messed up
        IR.startNodeElementId = I.elementId;
        IR.endNodeElementId = R.elementId;
    }
    console.log(IR);
    I.force_to_x = -100;
    R.force_to_x = 100;
    GraphData.nodes.push(I);
    GraphData.nodes.push(R);
    GraphData.links.push(IR);

    let neighbors = {};
    // explore surrounding nodes
    let neighborResults = await session.run('MATCH (known)-[rel:SIM]-(neighbor:INITIAL_HTML) WHERE elementId(known) in $ids RETURN *', { ids: [I.elementId, R.elementId] });
    for (let record of neighborResults.records) {
        let known = record.get("known");
        let rel = record.get("rel");
        let neighbor = record.get("neighbor");

        if (neighbor.elementId == I.elementId || neighbor.elementId == R.elementId) {
            continue;
        }

        if (neighbor.elementId in neighbors) {
            // node already exists
            neighbor = neighbors[neighbor.elementId];
        } else {
            neighbors[neighbor.elementId] = neighbor;
            GraphData.nodes.push(neighbor);
        }
        if (known.elementId === I.elementId) {
            neighbor.link_I = rel;
        } else {
            neighbor.link_R = rel;
        }
        GraphData.links.push(rel);
    }

    session.close();
    await prepare_job;


    graphElement.graphObj.d3Force("forceX", d3.forceX((n) => n.force_to_x || 0).strength((n) => n.force_to_x ? 1 : 0));
    graphElement.graphObj.d3Force("forceY", d3.forceY(0).strength((n) => n.force_to_x ? 1 : 0));
    graphElement.graphObj
        .nodeLabel((n) => {
            return `${n.properties.domain}<br/>
            @${n.properties.ip}<br/>
            in ${n.properties.version}<br/><br/>
            ${n.properties.doc_id}<br/>
            ${n.properties.redirect_index}<br/><br/>
            Similarities: (I|R)<br/>
            <pre>
L:   ${render_similarities_of_node(n, "similarity_levenshtein")}
LH:  ${render_similarities_of_node(n, "similarity_levenshtein_header")}
BoP: ${render_similarities_of_node(n, "similarity_bag_of_paths")}
RH:  ${render_similarities_of_node(n, "similarity_radoy_header")}
            </pre>
            `;
        })
    graphElement.graphObj
        .nodeCanvasObject((node, ctx, globalScale) => {
            ctx.fillStyle = "black";
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            if (node.elementId == I.elementId) {
                ctx.fillText("I", node.x, node.y);
            } else if (node == R) {
                ctx.fillText("R", node.x, node.y);
            }
        })
        .nodeCanvasObjectMode(() => "after");
    graphElement.graphObj.graphData(GraphData);
}

main()