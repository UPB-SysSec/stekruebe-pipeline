
function addScript(url) {
    if (addScript.loaded.has(url)) {
        return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
        var script = document.createElement('script');
        script.type = 'text/javascript';
        script.src = url;
        script.onload = resolve;
        document.getElementsByTagName('head')[0].appendChild(script);
    });
}
addScript.loaded = new Set();

neo4jdriver = null;
window.addEventListener('beforeunload', function (e) {
    if (neo4jdriver != null) {
        neo4jdriver.close();
    }
});

async function connectNeo4J(password) {
    await addScript("https://cdn.jsdelivr.net/npm/neo4j-driver@5.27.0/lib/browser/neo4j-web.min.js");
    const driver = neo4j.driver("neo4j+s://syssec-scanner6.cs.upb.de:7688", neo4j.auth.basic("neo4j", password));
    const session = driver.session();

    return await session.run('RETURN "Hello, World!"').then((result) => {
        neo4jdriver = driver;
        console.log("Connected to Neo4J");
        return driver;
    }).catch((error) => {
        console.error(error);
        driver.close();
        throw new Error("Login failed:" + error);
    }).finally(() => {
        session.close();
    })
}

let graphType = new URL(window.location).searchParams.get("g");


async function prepareGraph(graphElement, similarity_prop) {
    await addScript("https://unpkg.com/d3-force");
    switch (graphType) {
        case "3d":
            await addScript("https://unpkg.com/3d-force-graph");
            break;
        case "vr":
            await addScript("https://unpkg.com/3d-force-graph-vr");
            break;
        case "ar":
            await Promise.all(
                addScript("https://unpkg.com/aframe"),
                addScript("https://unpkg.com/@ar-js-org/ar.js"),
                addScript("https://unpkg.com/3d-force-graph-ar"));
            break;

        case "2d":
        default:
            graphType = "2d";
            await addScript("https://unpkg.com/force-graph");
            break;
    }

    var GraphT;
    switch (graphType) {
        case "3d":
            GraphT = ForceGraph3D();
            break;
        case "vr":
            GraphT = ForceGraphVR();
            break;
        case "ar":
            GraphT = ForceGraphAR();
            break;

        case "2d":
        default:
            GraphT = ForceGraph();
            break;
    }

    const COLORS = {
        BLACK: "#333333",
        BLUE: "#2BAEFF",
        PURPLE: "#6A0572",
        YELLOW: "#FFD166",
        WHITE: "#86E3CE",
    };

    let GraphObj = GraphT(graphElement);
    graphElement.graphObj = GraphObj;
    GraphObj
        .nodeId('elementId')
        .linkSource('startNodeElementId')
        .linkTarget('endNodeElementId')
        .linkColor((l) => COLORS[l.properties.first_color])
        .nodeColor((n) => {
            if (n.labels.includes("REDIRECT_HTML")) {
                // blue
                if (n.properties.ip.includes(":")) {
                    // ipv6
                    return "#2BAEFF";
                }
                return "#6184D8";
            }
            return "#ED6A5A";
        })
        .nodeVal("nodeSize")
        .nodeLabel((n) => {
            return `${n.properties.domain}<br/>@${n.properties.ip}<br/>in ${n.properties.version}<br/><br/>${n.properties.doc_id}<br/>${n.properties.redirect_index}`;
        })
        .linkLabel((l) => {
            return `${l.properties.first_color}<br/>Levenshtein: ${l.properties.similarity_levenshtein}<br/>Levenshtein Head: ${l.properties.similarity_levenshtein_header}<br/>BoP: ${l.properties.similarity_bag_of_paths}<br/>Radoy: ${l.properties.similarity_radoy_header}`;
        })
        .linkDirectionalArrowLength((l) => {
            if (l.properties.first_color == "WHITE") {
                return 20;
            }
            return 0;
        })
        .linkWidth(l => l.linkWidth || 1)
        .linkCurvature(l => {
            if (l.properties.first_color == "WHITE") {
                return 0.2;
            }
            return 0;
        })
        .onNodeClick((node, event) => {
            navigator.clipboard.writeText(node.properties.doc_id);
        })
        .onLinkClick((link, event) => {
            navigator.clipboard.writeText(`MATCH (a)-[r]->(b) WHERE elementId(r)="${link.elementId}" RETURN a,r,b`);
        });
    await refreshGraphDistances(graphElement, similarity_prop);

    // handle resize
    window.addEventListener('resize', () => {
        GraphObj.width(graphElement.offsetWidth).height(graphElement.offsetHeight);
    });
}
async function refreshGraphDistances(graphElement, similarity_prop) {
    graphElement.graphObj
        .linkLineDash(l => {
            if (l.properties[[similarity_prop]] == undefined) {
                return [1, 2];
            }
            return null;
        })
        .d3Force('link', d3.forceLink()
            .strength((l) => l.properties[similarity_prop] + 0.1 || 0.5)
            .distance((l) => l.linkDistance || null)
        )
}
