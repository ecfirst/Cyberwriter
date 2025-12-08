import * as Y from "yjs";

import { type ModelHandler } from "../base_handler";

/**
 * In-memory collaborative document for project workbook data.
 *
 * Workbook updates are persisted through the existing Django endpoints; the
 * collab server simply brokers live updates between users so they see each
 * other's changes immediately and avoid overwriting newer edits.
 */
const ProjectWorkbookHandler: ModelHandler<null> = {
    async load() {
        const doc = new Y.Doc();
        return [doc, null];
    },

    async save() {
        // No-op: workbook persistence continues to go through the standard
        // Django views. The collab server keeps the shared Yjs document in
        // memory to broadcast live updates between clients.
        return;
    },
};

export default ProjectWorkbookHandler;
