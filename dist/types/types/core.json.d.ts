export type corejson = {
    [index: string]: {
        /** f.e: [ 'CVE-2023-46809' ] */
        cve: string[];
        /** f.e: 'https://nodejs.org/en/blog/vulnerability/february-2024-security-releases/' */
        ref: string;
        /** f.e: '18.x || 20.x || 21.x' */
        vulnerable: string;
        /** f.e:  '^18.19.1 || ^20.11.1 || ^21.6.2'  */
        patched: string;
        /** f.e: "memory overread when parsing invalid NAPTR responses" */
        description: string;
        /** f.e: 'A vulnerability in the privateDecrypt() API of the crypto library, allowed a covert timing side-channel during PKCS#1 v1.5 padding error handling.' */
        overview: string;
        /** f.e: [ 'all' ] */
        affectedEnvironments: string[];
        severity: "unknown" | "medium" | "low" | "high" | "critical";
    };
};
