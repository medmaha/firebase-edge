import type { EmailSender } from './types';

/** Ready-made EmailSender for Resend (https://resend.com). */
export function resendEmailSender(opts: {
    apiKey: string;
    from: string;
    fetchFn?: typeof fetch;
}): EmailSender {
    const doFetch = opts.fetchFn ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
    return async ({ to, subject, text }) => {
        const res = await doFetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${opts.apiKey}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ from: opts.from, to, subject, text }),
        });
        if (!res.ok) console.error('Resend failed:', res.status, await res.text().catch(() => ''));
        return res.ok;
    };
}
