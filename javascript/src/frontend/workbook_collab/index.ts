import { HocuspocusProvider } from "@hocuspocus/provider";

type Snapshot = {
    workbook_data?: unknown;
    data_artifacts?: unknown;
};

type Listener = (snapshot: Snapshot) => void;

function readJsonScript(id: string): unknown | null {
    const el = document.getElementById(id);
    if (!el || !el.textContent) return null;
    try {
        return JSON.parse(el.textContent);
    } catch (e) {
        console.error("Could not parse JSON from", id, e);
        return null;
    }
}

function readText(id: string): string | null {
    const el = document.getElementById(id);
    if (!el) return null;
    return el.textContent || null;
}

function clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value ?? {}));
}

function initProvider() {
    const url = readText("yjs-url");
    const id = readText("yjs-object-id");
    const username = readText("yjs-username");
    const jwt = readText("yjs-jwt");

    if (!url || !id || !username || !jwt) {
        console.warn("Missing YJS connection info; live workbook collaboration disabled.");
        return null;
    }

    const provider = new HocuspocusProvider({
        url,
        name: `project_workbook/${id}`,
        token: () => jwt,
        connect: true,
    });

    provider.awareness?.setLocalStateField("user", { name: username });

    return provider;
}

function setupCollab() {
    const provider = initProvider();
    if (!provider) return;

    const state = provider.document.getMap<unknown>("state");
    const initialSnapshot: Snapshot = {
        workbook_data: readJsonScript("project-workbook-data") || {},
        data_artifacts: readJsonScript("project-data-artifacts") || {},
    };

    const listeners = new Set<Listener>();

    const emit = () => {
        const snapshot: Snapshot = {
            workbook_data: clone(state.get("workbook_data") || {}),
            data_artifacts: clone(state.get("data_artifacts") || {}),
        };
        listeners.forEach((cb) => cb(snapshot));
    };

    const pushSnapshot = (snapshot: Snapshot) => {
        provider.document.transact(() => {
            if (snapshot.workbook_data !== undefined) {
                state.set("workbook_data", clone(snapshot.workbook_data));
            }
            if (snapshot.data_artifacts !== undefined) {
                state.set("data_artifacts", clone(snapshot.data_artifacts));
            }
        });
    };

    const ready = new Promise<void>((resolve) => {
        const onSync = (event: { state: boolean }) => {
            if (!event.state) return;
            provider.off("synced", onSync);
            if (!state.has("workbook_data") && initialSnapshot.workbook_data) {
                pushSnapshot(initialSnapshot);
            }
            emit();
            resolve();
        };
        provider.on("synced", onSync);
    });

    state.observe(emit);

    const subscribe = (cb: Listener) => {
        listeners.add(cb);
        return () => listeners.delete(cb);
    };

    const api = {
        ready,
        subscribe,
        pushSnapshot,
        getSnapshot: () => ({
            workbook_data: clone(state.get("workbook_data") || {}),
            data_artifacts: clone(state.get("data_artifacts") || {}),
        }),
    } satisfies WorkbookCollabApi;

    (window as any).gwWorkbookCollab = api;
}

type WorkbookCollabApi = {
    ready: Promise<void>;
    subscribe: (cb: Listener) => () => void;
    pushSnapshot: (snapshot: Snapshot) => void;
    getSnapshot: () => Snapshot;
};

declare global {
    interface Window {
        gwWorkbookCollab?: WorkbookCollabApi;
    }
}

document.addEventListener("DOMContentLoaded", setupCollab);
