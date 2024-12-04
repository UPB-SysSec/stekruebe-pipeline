//login form stuff
if (localStorage.getItem("neo4jpass") != null) {
    document.getElementById("password").value = localStorage.getItem("neo4jpass");
}

loginform.onsubmit = (e) => {
    e.preventDefault()
    const password = document.getElementById("password").value;

    connectNeo4J(password)
        .then((driver) => {
            localStorage.setItem("neo4jpass", password);
            initGraph();
        })
        .catch((error) => {
            loginfeedback.innerText = error;
        });
}

function addNonDuplicate(element, identity, duplicateset, listtoaddto) {
    if (!duplicateset.has(identity)) {
        duplicateset.add(identity);
        listtoaddto.push(element);
    }
}

async function initGraph() {
    let graphElement = document.getElementById("graph");
    let similarity_prop = "similarity_levenshtein";

    await prepareGraph(graphElement, similarity_prop)

    let session = null;
    let pushedNodeIds = new Set();
    let pushedRelationIds = new Set();

    GraphData = {
        nodes: [],
        links: []
    };
    try {
        session = neo4jdriver.session();
        // results = await session.run(`MATCH (a)-[aI:SIM]-(I)-[IR:SIM {first_color:"WHITE"}]-(R:REDIRECT_HTML)-[Rb:SIM]-(b)-[ab:SIM]-(a)
        //         WHERE IR[$sim_typ] < 0.1
        //           AND ab[$sim_typ] < 0.1
        //           AND aI[$sim_typ] > 0.9
        //           AND Rb[$sim_typ] > 0.9
        //         RETURN I,IR,R LIMIT 20`, { sim_typ: similarity_prop });
        // results = await session.run(`MATCH (I)-[IR:SIM {first_color:"WHITE"}]-(R:REDIRECT_HTML)
        //         WHERE IR[$sim_typ] < 0.1
        //           AND EXISTS {
        //             (I)-[A:SIM]-(a)-[ab:SIM]-(b)-[B:SIM]-(R)
        //             WHERE ab[$sim_typ] < 0.1
        //                 AND A[$sim_typ] > 0.9
        //                 AND B[$sim_typ] > 0.9
        //                 AND a.domain <> b.domain
        //           }
        //         RETURN I,IR,R
        //         SKIP 20
        //         LIMIT 10`, { sim_typ: similarity_prop });
        results = await session.run(`MATCH(I) - [IR: SIM { first_color: "WHITE" }] - (R:REDIRECT_HTML)
                WITH I, IR, R, COLLECT { 
                    MATCH(R) - [B: SIM] - (b)
                    WHERE I.domain <> b.domain
                      AND B[$sim_typ] > 0.9
                      RETURN[B, b]
                    } as _bs
                WHERE size(_bs) > 0 AND size(_bs) < 5 AND IR[$sim_typ] < 0.1
                RETURN I, IR, R
                LIMIT 1`, { sim_typ: similarity_prop });
        for (let record of results.records) {
            let I = record.get("I");
            let R = record.get("R");
            let IR = record.get("IR");
            I.nodeSize = 4;
            R.nodeSize = 4;
            IR.linkWidth = 4;
            IR.linkDistance = 200;
            addNonDuplicate(I, I.elementId, pushedNodeIds, GraphData.nodes);
            addNonDuplicate(R, R.elementId, pushedNodeIds, GraphData.nodes);
            addNonDuplicate(IR, IR.elementId, pushedRelationIds, GraphData.links);
        }
        // explore surrounding nodes
        furtherResults = await session.run('MATCH (I)-[IO:SIM]-(O) WHERE elementId(I) in $ids RETURN IO,O', { ids: Array.from(pushedNodeIds) });
        for (let record of furtherResults.records) {
            addNonDuplicate(record.get("O"), record.get("O").elementId, pushedNodeIds, GraphData.nodes);
            addNonDuplicate(record.get("IO"), record.get("IO").elementId, pushedRelationIds, GraphData.links);
        }
    } finally {
        if (session != null) {
            session.close();
        }
    }

    graphElement.graphObj.graphData(GraphData);
}
