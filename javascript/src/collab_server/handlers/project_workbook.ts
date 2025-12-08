import { type TypedDocumentNode } from "@apollo/client";
import { gql } from "@apollo/client/core";
import { simpleModelHandler } from "../base_handler";
import * as Y from "yjs";

type GetProjectWorkbookQuery = {
    project_by_pk?: {
        workbookData?: any;
        dataResponses?: any;
    } | null;
};

type SetProjectWorkbookMutation = {
    update_project_by_pk?: { id: number } | null;
};

const GET: TypedDocumentNode<GetProjectWorkbookQuery, { id: number }> = gql(`
    query GET_PROJECT_WORKBOOK($id: bigint!) {
        project_by_pk(id: $id) {
            workbookData
            dataResponses
        }
    }
`);

const SET: TypedDocumentNode<
    SetProjectWorkbookMutation,
    { id: number; workbookData: any; dataResponses: any }
> = gql(`
    mutation SET_PROJECT_WORKBOOK(
        $id: bigint!,
        $workbookData: jsonb!,
        $dataResponses: jsonb!
    ) {
        update_project_by_pk(
            pk_columns: { id: $id },
            _set: { workbookData: $workbookData, dataResponses: $dataResponses }
        ) {
            id
        }
    }
`);

const ProjectWorkbookHandler = simpleModelHandler<
    GetProjectWorkbookQuery,
    SetProjectWorkbookMutation,
    { id: number; workbookData: any; dataResponses: any },
    Record<string, never>
>(
    GET,
    SET,
    (doc, res) => {
        const obj = res.project_by_pk;
        if (!obj) throw new Error("No object");
        const plainFields = doc.get("plain_fields", Y.Map<string>);
        plainFields.set(
            "workbookData",
            JSON.stringify(obj.workbookData ?? {}, null, 2)
        );
        plainFields.set(
            "dataResponses",
            JSON.stringify(obj.dataResponses ?? {}, null, 2)
        );
        return {};
    },
    (doc, id) => {
        const plainFields = doc.get("plain_fields", Y.Map<string>);
        const parseJsonField = (key: string) => {
            const value = plainFields.get(key);
            if (!value) return {};
            try {
                return JSON.parse(value);
            } catch (error) {
                throw new Error(`Invalid JSON in ${key}`);
            }
        };

        return {
            id,
            workbookData: parseJsonField("workbookData"),
            dataResponses: parseJsonField("dataResponses"),
        };
    }
);

export default ProjectWorkbookHandler;
