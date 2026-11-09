/**
 * Cribbed from https://github.com/guardian/csnx/blob/main/libs/%40guardian/libs/src/getErrorMessage/getErrorMessage.ts
 * It would be better to install the @guardian/libs package and import it from there,
 * but we'd need to upgrade TypeScript and some other stuff in this project first.
 */

type ErrorWithMessage = {
  message: string;
};

function isErrorWithMessage(error: unknown): error is ErrorWithMessage {
  return (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof (error as Record<string, unknown>).message === "string"
  );
}

function toErrorWithMessage(maybeError: unknown): ErrorWithMessage {
  if (isErrorWithMessage(maybeError)) {
    return maybeError;
  }

  try {
    if (typeof maybeError === "string") {
      return new Error(maybeError);
    }
    return new Error(JSON.stringify(maybeError));
  } catch {
    // fallback in case there's an error stringifying the maybeError
    // like with circular references for example.
    return new Error(String(maybeError));
  }
}

export function getErrorMessage(error: unknown): string {
  return toErrorWithMessage(error).message;
}
