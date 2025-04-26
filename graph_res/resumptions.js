if (localStorage.getItem("neo4jpass") != null) {
    document.getElementById("password").value = localStorage.getItem("neo4jpass");
}

loginform.onsubmit = (e) => {
    e.preventDefault()
    const password = document.getElementById("password").value;

    connectNeo4J(password)
        .then((driver) => {
            localStorage.setItem("neo4jpass", password);
            load_data();
        })
        .catch((error) => {
            loginfeedback.innerText = error;
        });
}

neo4jSession = null;
let similarity_prop = "similarity_levenshtein";

const _SIMILARITIES = {
    "similarity_levenshtein": "L",
    "similarity_levenshtein_header": "LH",
    "similarity_bag_of_paths": "BOP",
    "similarity_radoy_header": "RH",
}

function render_similarities(edge, highlight_prop, outer_typ) {
    let ret = document.createElement(outer_typ);
    ret.classList.add("similarity");
    for (let [prop, label] of Object.entries(_SIMILARITIES)) {
        let value_text;
        if (edge.properties[prop] === undefined) {
            value_text = "N/A";
        } else if (typeof edge.properties[prop] === "number") {
            value_text = edge.properties[prop].toFixed(2);
        } else {
            value_text = edge.properties[prop];
        }

        let txt = `${label}: ${value_text}`;
        if (prop == highlight_prop) {
            ret.appendChild(document.createElement("b")).innerText = txt;
        } else {
            ret.appendChild(document.createElement("span")).innerText = txt;
        }
        ret.appendChild(document.createElement("br"));
    }
    return ret;
}

function render_other_nodes(other_list, outer_typ) {
    let other_domains = new Set();
    for (let other of other_list) {
        other_domains.add(other[0].properties.domain);
    }
    ret = document.createElement(outer_typ);
    ret.innerText = `${other_domains.size} domains / ${other_list.length} nodes`;
    return ret;
}

async function fetch_mongo(doc_id) {
    let response = await fetch(`/mongo/${doc_id}`);
    let data = await response.json();
    return data;
}

async function load_data() {
    if (neo4jSession == null) {
        neo4jSession = neo4jdriver.session();
        window.addEventListener('beforeunload', function (e) {
            if (neo4jSession != null) {
                neo4jSession.close();
            }
        });
    }

    let table = document.getElementById("resumptions_table");

    let query = `
        MATCH (I)-[IR: SIM { first_color: "WHITE" }]-(R:REDIRECT_HTML)
                WHERE IR.${similarity_prop} < 0.1
                WITH I, IR, R,
                    COLLECT { 
                        MATCH (a)-[A:SIM]-(I)
                        WHERE A.${similarity_prop} > 0.9
                          AND a<>R
                        RETURN[a, A]
                        ORDER BY A.${similarity_prop} DESC
                    } as other_a,
                    COLLECT {
                        MATCH (R)-[B: SIM]-(b)
                        WHERE B.${similarity_prop} > 0.9
                          AND I.domain <> b.domain
                          AND I.cert_fingerprint <> b.cert_fingerprint
                        RETURN[b, B]
                        ORDER BY B.${similarity_prop} DESC
                    } as other_b
                WHERE size(other_b) > 0
                RETURN I, IR, R, other_a, other_b
                ORDER BY other_b[0][0].ip ASC
                LIMIT 1000
        `;
    console.log(query);
    results = await neo4jSession.run(query);
    console.log(`Got ${results.records.length} results`);
    for (let record of results.records) {
        let I = record.get("I");
        let IR = record.get("IR");
        let R = record.get("R");
        let other_a = record.get("other_a");
        let other_b = record.get("other_b");

        closest_b = other_b[0];

        let row = document.createElement("tr");
        // Edge ID
        let td_edge_id = document.createElement("td");
        let link_to_edge_id = document.createElement("a");
        link_to_edge_id.href = `/resumption.html?edge_id=${IR.elementId}`;
        link_to_edge_id.innerText = IR.elementId;
        td_edge_id.appendChild(link_to_edge_id);
        row.appendChild(td_edge_id);
        // Domain
        row.appendChild(document.createElement("td")).innerText = I.properties.domain;
        // From IP
        row.appendChild(document.createElement("td")).innerText = I.properties.ip;
        // Similarity
        row.appendChild(render_similarities(IR, similarity_prop, "td"));
        // To IP
        row.appendChild(document.createElement("td")).innerText = R.properties.ip;

        // Similarity
        row.appendChild(render_similarities(closest_b[1], similarity_prop, "td"));

        // Determined Domain
        row.appendChild(document.createElement("td")).innerText = closest_b[0].properties.domain;

        // Other possible R domains
        row.appendChild(render_other_nodes(other_b, "td"));
        // Other possible I domains
        row.appendChild(render_other_nodes(other_a, "td"));

        // bodies for I and R
        if (I.properties.doc_id != R.properties.doc_id) {
            throw new Error("I and R should have the same doc_id");
        }
        row.additional_data = {
            "I": I,
            "IR": IR,
            "R": R,
            "other_a": other_a,
            "other_b": other_b,
        }
        fetch_mongo(I.properties.doc_id).then((data) => {
            row.additional_data.zgrab_IR = data;
        })
        fetch_mongo(other_b[0][0].properties.doc_id).then((data) => {
            row.additional_data.zgrab_b = data;
        })

        row.addEventListener("mouseenter", table_hover);

        table.appendChild(row);
    }

}

async function render_foreign_body(zgrab_output, orig_domain, div_body) {
    div_body.innerHTML = "";
    let response = zgrab_output.data.http.result.response;
    div_body.appendChild(document.createElement("span")).innerText = response.status_line;
    div_body.appendChild(document.createElement("br"));
    div_body.appendChild(document.createElement("i")).innerText = response.content_title;
    div_body.appendChild(document.createElement("br"));
    div_body.appendChild(document.createElement("b")).innerText = response.body.indexOf(orig_domain) >= 0 ? "Contains original domain" : "";
    div_body.appendChild(document.createElement("br"));
    div_body.appendChild(document.createElement("pre")).innerText = response.body;
}

async function table_hover(event) {
    let additional_data = event.target.additional_data;
    let div_info = document.getElementById("row-info");
    let div_body_I = document.getElementById("row-body-I");
    let div_body_R = document.getElementById("row-body-R");
    let div_body_b = document.getElementById("row-body-b");

    if (!additional_data.zgrab_IR || !additional_data.zgrab_b) {
        div_info.innerText = "Still loading...";
        return;
    }

    div_info.innerText = "Hello World";
    let orig_domain = additional_data.I.properties.domain;
    render_foreign_body(additional_data.zgrab_IR.initial, orig_domain, div_body_I);
    render_foreign_body(additional_data.zgrab_IR.redirect[additional_data.R.properties.redirect_index], orig_domain, div_body_R);
    render_foreign_body(additional_data.zgrab_b.initial, orig_domain, div_body_b);
}

