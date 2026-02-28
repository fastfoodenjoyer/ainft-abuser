import json
from typing import Any, AsyncGenerator

from curl_cffi import AsyncSession
from curl_cffi.requests.exceptions import RequestException, Timeout, ProxyError, CurlError

class AsyncAinftClient:
    """
    Asynchronous client for interacting with chat.ainft.com models using generated API keys.
    """
    BASE_URL = "https://chat.ainft.com/webapi/chat"
    
    # Map common model prefixes to their providers
    PROVIDER_MAP = {
        "gpt": "openai",
        "o1": "openai",
        "o3": "openai",
        "claude": "anthropic",
        "gemini": "google",
        "deepseek": "deepseek",
        "llama": "meta"
    }

    def __init__(self, api_key: str, proxies: list[str] | str | None = None):
        self.api_key = api_key
        
        if isinstance(proxies, str):
            self.proxies = [proxies]
        elif proxies and isinstance(proxies, list):
            self.proxies = proxies
        else:
            self.proxies = [None]
            
        self.proxy_index = 0
        self._init_session()

    def _init_session(self):
        self.session = AsyncSession(impersonate="chrome")
        proxy = self.proxies[self.proxy_index]
        if proxy:
            if "://" not in proxy:
                proxy = f"http://{proxy}"
            self.session.proxies = {"http": proxy, "https": proxy}

    def _rotate_proxy(self):
        if len(self.proxies) > 1:
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
            print(f"[AsyncAinftClient] Switching to next proxy: {self.proxies[self.proxy_index]}")
            self._init_session()
        elif self.proxies[0] is not None:
            print(f"[AsyncAinftClient] Reconnecting with the same proxy...")
            self._init_session()

    async def _request(self, method: str, url: str, max_retries: int = None, **kwargs):
        if max_retries is None:
            max_retries = max(3, len(self.proxies))
            
        last_exc = None
        for attempt in range(max_retries):
            try:
                response = await self.session.request(method, url, **kwargs)
                return response
            except (RequestException, Timeout, ProxyError, CurlError, Exception) as e:
                last_exc = e
                print(f"[AsyncAinftClient] Network error on attempt {attempt + 1}: {type(e).__name__}: {str(e)}")
                self._rotate_proxy()
                
        raise Exception(f"Request failed after {max_retries} attempts. Last error: {last_exc}")

    async def close(self):
        """Close the underlying session."""
        # try:
        #     import inspect
        #     # handle session closes gracefully
        #     if hasattr(self.session, "close") and inspect.iscoroutinefunction(self.session.close):
        #         await self.session.close()
        #     else:
        #         self.session.close()
        # except:
        #     pass
        await self.session.close()

    def _get_provider_for_model(self, model: str) -> str:
        model_lower = model.lower()
        for prefix, provider in self.PROVIDER_MAP.items():
            if model_lower.startswith(prefix):
                return provider
        # Default fallback
        return "openai"

    async def chat_completions(
        self,
        messages: list[dict[str, str]],
        model: str = "gpt-5-mini",
        stream: bool = False,
        temperature: float = 1.0,
        top_p: float = 1.0,
        frequency_penalty: float = 0.0,
        presence_penalty: float = 0.0
    ):
        """
        Sends a chat completion request to the given model asynchronously.
        Returns a string if stream=False, or an AsyncGenerator yielding text chunks if stream=True.
        """
        provider = self._get_provider_for_model(model)
        url = f"{self.BASE_URL}/{provider}"
        
        headers = {
            'accept': 'application/json' if not stream else 'text/event-stream',
            'authorization': f'Bearer {self.api_key}',
            'content-type': 'application/json'
        }
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream,
            "temperature": temperature,
            "top_p": top_p,
            "frequency_penalty": frequency_penalty,
            "presence_penalty": presence_penalty
        }
        
        if stream:
            return self._stream_response(url, headers, payload)
        else:
            return await self._sync_response(url, headers, payload)

    async def _sync_response(self, url: str, headers: dict[str, str], payload: dict[str, Any]) -> str:
        response = await self._request("POST", url, json=payload, headers=headers)
        if response.status_code != 200:
            raise Exception(f"API Error {response.status_code}: {response.text}")
            
        try:
            # Try to parse as normal JSON if stream=False actually works
            data = response.json()
            if "choices" in data:
                return data["choices"][0]["message"]["content"]
            elif "message" in data:
                return data["message"]["content"]
        except Exception:
            pass
            
        # Default fallback to stream parser if simple json fails
        full_text = ""
        for line in response.text.splitlines():
            if line.startswith("data: "):
                data_str = line[6:].strip()
                if data_str == '"STOP"' or data_str == '[DONE]':
                    break
                
                if data_str.startswith("{"):
                    pass
                elif data_str.startswith('"') and data_str.endswith('"'):
                    try:
                        chunk = json.loads(data_str)
                        if chunk.lower() != "stop":
                            full_text += chunk
                    except:
                        pass
        return full_text.strip()

    async def _stream_response(self, url: str, headers: dict[str, str], payload: dict[str, Any]) -> AsyncGenerator[str, None]:
        response = await self._request("POST", url, json=payload, headers=headers, stream=True)
        if response.status_code != 200:
            error_text = response.content.decode('utf-8', errors='ignore')
            raise Exception(f"API Error {response.status_code}: {error_text}")
            
        async for line_bytes in response.aiter_lines():
            if not line_bytes:
                continue
            line = line_bytes.decode('utf-8')
            if line.startswith("data: "):
                data_str = line[6:].strip()
                if data_str == '"STOP"' or data_str == '[DONE]':
                    break
                
                # Check for usage/speed JSON stats or empty dicts
                if data_str.startswith("{"):
                    pass
                elif data_str.startswith('"') and data_str.endswith('"'):
                    try:
                        chunk = json.loads(data_str)
                        if chunk.lower() != "stop":
                            yield chunk
                    except:
                        pass
                    # Sometimes it's a JSON block with usage stats
                    try:
                        obj = json.loads(data_str)
                        if "choices" in obj:
                            delta = obj["choices"][0].get("delta", {})
                            if "content" in delta:
                                yield delta["content"]
                    except:
                        pass

if __name__ == "__main__":
    import asyncio

    async def main():
        TEST_API_KEY = "sk-asdf..."
        text = "Tell me a story about a robot learning to love."
        stream = True
        model = "gemini-3-flash-preview"

        client = AsyncAinftClient(api_key=TEST_API_KEY)

        print(f"Testing {model} (Stream={stream})...")
        print(f"Input: {text}")
        messages = [{"role": "user", "content": text}]
        print("Answer:")
        
        try:
            if stream:
                async for chunk in await client.chat_completions(messages=messages, model=model, stream=stream):
                    print(chunk, end="", flush=True)
            else:
                response = await client.chat_completions(messages=messages, model=model, stream=stream)
                print(response)
        finally:
            await client.close()

        print("\n\nDone!")

    asyncio.run(main())
