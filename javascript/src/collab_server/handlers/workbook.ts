import { gql } from "../../__generated__/";
import { simpleModelHandler } from "../base_handler";
import * as Y from "yjs";

function jsonToY(value: any): any {
    if (value === undefined) return null;
    if (Array.isArray(value)) {
        const arr = new Y.Array();
        arr.push(value.map(jsonToY));
        return arr;
    }
    if (value && typeof value === "object") {
        const map = new Y.Map<any>();
        for (const [k, v] of Object.entries(value)) {
            map.set(k, jsonToY(v));
        }
        return map;
    }
    return value;
}

function yToJson(value: any): any {
    if (value instanceof Y.Array) return value.toArray().map(yToJson);
    if (value instanceof Y.Map) {
        const obj: Record<string, any> = {};
        for (const [k, v] of value.entries()) obj[k] = yToJson(v);
        return obj;
    }
    return value;
}

const GET = gql(`
    query GET_WORKBOOK($id: bigint!) {
        project_by_pk(id: $id) {
            workbook_data
        }
    }
`);

const SET = gql(`
    mutation SET_WORKBOOK($id: bigint!, $workbook_data: jsonb!) {
        update_project_by_pk(
            pk_columns: { id: $id }
            _set: { workbook_data: $workbook_data }
        ) {
            id
        }
    }
`);

const WorkbookHandler = simpleModelHandler(
    GET,
    SET,
    (doc, res) => {
        const data = res.project_by_pk?.workbook_data ?? {};
        const map = doc.getMap("workbook");
        map.clear();
        if (data && typeof data === "object") {
            for (const [k, v] of Object.entries(data)) {
                map.set(k, jsonToY(v));
            }
        }
        return null;
    },
    (doc, id) => {
        const workbookMap = doc.getMap("workbook");
        const workbook_data: Record<string, any> = yToJson(workbookMap);
        return { id, workbook_data };
    }
);

export default WorkbookHandler;
