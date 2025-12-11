import { useEffect } from "react";
import { createRoot } from "react-dom/client";
import * as Y from "yjs";

import PageGraphqlProvider from "../../graphql/client";
import { usePageConnection } from "../connection";

type SubmitOverride = (
    payload: any,
    onSuccess?: () => void,
    renderOptions?: any
) => Promise<void> | void;

type WorkbookCollabApi = {
    replaceState?: (data: any, renderOptions?: any) => void;
    setSubmitOverride?: (fn: SubmitOverride | null) => void;
    setSaveError?: (hasError: boolean) => void;
};

declare global {
    interface Window {
        gwWorkbookCollabApi?: WorkbookCollabApi;
    }
}

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

function mergeIntoMap(target: Y.Map<any>, patch: any) {
    if (!patch || typeof patch !== "object") return;

    for (const [key, value] of Object.entries(patch)) {
        if (key === "remove_nexpose" && typeof value === "string") {
            target.delete(value);
            continue;
        }

        if (value === undefined) continue;
        if (value === null) {
            target.set(key, null);
            continue;
        }
        if (Array.isArray(value)) {
            target.set(key, jsonToY(value));
            continue;
        }
        if (value && typeof value === "object") {
            const existing = target.get(key);
            if (existing instanceof Y.Map) mergeIntoMap(existing, value);
            else target.set(key, jsonToY(value));
            continue;
        }
        target.set(key, value);
    }
}

function WorkbookCollabBridge() {
    const { provider, status } = usePageConnection({ model: "workbook" });

    useEffect(() => {
        const api = window.gwWorkbookCollabApi;
        if (!api) return;
        api.setSaveError?.(status === "error");
    }, [status]);

    useEffect(() => {
        const api = window.gwWorkbookCollabApi;
        if (!api) return;

        const map = provider.document.getMap<any>("workbook");
        const pushState = (renderOptions?: any) => {
            api.replaceState?.(yToJson(map), renderOptions);
        };

        const observer = () => pushState();
        map.observeDeep(observer);
        pushState();

        api.setSubmitOverride?.(
            async (payload: any, onSuccess?: () => void, renderOptions?: any) => {
                provider.document.transact(() => mergeIntoMap(map, payload));
                onSuccess?.();
                pushState(renderOptions);
            }
        );

        return () => {
            map.unobserveDeep(observer);
            api.setSubmitOverride?.(null);
        };
    }, [provider]);

    return null;
}

document.addEventListener("DOMContentLoaded", () => {
    const mount = document.createElement("div");
    mount.id = "workbook-collab-root";
    document.body.appendChild(mount);

    const root = createRoot(mount);
    root.render(
        <PageGraphqlProvider>
            <WorkbookCollabBridge />
        </PageGraphqlProvider>
    );
});
