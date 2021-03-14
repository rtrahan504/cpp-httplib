//
// Copyright (c) 2020 Yuji Hirose, 2021 Russell Trahan. All rights reserved. 
// Portions of this project have been copied from cpp-httplib by Yuji Hirose and modified by Russell Trahan.
//  
// MIT License
//

#include "httplib.h"
#include "Utility.h"

namespace httplib
{
	namespace detail
	{
		bool ci::operator()(const std::string& s1, const std::string& s2) const
		{
			return std::lexicographical_compare(
				s1.begin(), s1.end(), s2.begin(), s2.end(),
				[](char c1, char c2)
				{
					return ::tolower(c1) < ::tolower(c2);
				});
		}
	}

	DataSink::DataSink() : os(&sb_), sb_(*this)
	{
	}
	DataSink::data_sink_streambuf::data_sink_streambuf(DataSink& sink) : sink_(sink)
	{
	}
	std::streamsize DataSink::data_sink_streambuf::xsputn(const char* s, std::streamsize n)
	{
		sink_.write(s, static_cast<size_t>(n));
		return n;
	}


	ContentReader::ContentReader(Reader reader, MultipartReader multipart_reader)
		: reader_(reader), multipart_reader_(multipart_reader)
	{
	}
	bool ContentReader::operator()(MultipartContentHeader header, ContentReceiver receiver) const
	{
		return multipart_reader_(header, receiver);
	}
	bool ContentReader::operator()(ContentReceiver receiver) const
	{
		return reader_(receiver);
	}


	// Request implementation
	bool Request::has_header(const char* key) const
	{
		return detail::has_header(headers, key);
	}

	std::string Request::get_header_value(const char* key, size_t id) const
	{
		return detail::get_header_value(headers, key, id, "");
	}

	size_t Request::get_header_value_count(const char* key) const
	{
		auto r = headers.equal_range(key);
		return static_cast<size_t>(std::distance(r.first, r.second));
	}

	void Request::set_header(const char* key, const char* val)
	{
		if (!detail::has_crlf(key) && !detail::has_crlf(val))
		{
			headers.emplace(key, val);
		}
	}

	void Request::set_header(const char* key, const std::string& val)
	{
		if (!detail::has_crlf(key) && !detail::has_crlf(val.c_str()))
		{
			headers.emplace(key, val);
		}
	}

	bool Request::has_param(const char* key) const
	{
		return params.find(key) != params.end();
	}

	std::string Request::get_param_value(const char* key, size_t id) const
	{
		auto it = params.find(key);
		std::advance(it, static_cast<ssize_t>(id));
		if (it != params.end())
		{
			return it->second;
		}
		return std::string();
	}

	size_t Request::get_param_value_count(const char* key) const
	{
		auto r = params.equal_range(key);
		return static_cast<size_t>(std::distance(r.first, r.second));
	}

	bool Request::is_multipart_form_data() const
	{
		const auto& content_type = get_header_value("Content-Type");
		return !content_type.find("multipart/form-data");
	}

	bool Request::has_file(const char* key) const
	{
		return files.find(key) != files.end();
	}

	MultipartFormData Request::get_file_value(const char* key) const
	{
		auto it = files.find(key);
		if (it != files.end())
		{
			return it->second;
		}
		return MultipartFormData();
	}

	// Response implementation
	bool Response::has_header(const char* key) const
	{
		return headers.find(key) != headers.end();
	}

	std::string Response::get_header_value(const char* key, size_t id) const
	{
		return detail::get_header_value(headers, key, id, "");
	}

	size_t Response::get_header_value_count(const char* key) const
	{
		auto r = headers.equal_range(key);
		return static_cast<size_t>(std::distance(r.first, r.second));
	}

	void Response::set_header(const char* key, const char* val)
	{
		if (!detail::has_crlf(key) && !detail::has_crlf(val))
		{
			headers.emplace(key, val);
		}
	}

	void Response::set_header(const char* key, const std::string& val)
	{
		if (!detail::has_crlf(key) && !detail::has_crlf(val.c_str()))
		{
			headers.emplace(key, val);
		}
	}

	void Response::set_redirect(const char* url, int stat)
	{
		if (!detail::has_crlf(url))
		{
			set_header("Location", url);
			if (300 <= stat && stat < 400)
			{
				this->status = stat;
			}
			else
			{
				this->status = 302;
			}
		}
	}

	void Response::set_content(const char* s, size_t n, const char* content_type)
	{
		body.assign(s, n);
		set_header("Content-Type", content_type);
	}

	void Response::set_content(std::string s, const char* content_type)
	{
		body = std::move(s);
		set_header("Content-Type", content_type);
	}

	void Response::set_content_provider(size_t in_length, ContentProvider provider, std::function<void()> resource_releaser)
	{
		assert(in_length > 0);
		content_length_ = in_length;
		content_provider_ = [provider](size_t offset, size_t length, DataSink& sink)
		{
			return provider(offset, length, sink);
		};
		content_provider_resource_releaser_ = resource_releaser;
	}

	void Response::set_chunked_content_provider(ChunkedContentProvider provider, std::function<void()> resource_releaser)
	{
		content_length_ = 0;
		content_provider_ = [provider](size_t offset, size_t, DataSink& sink)
		{
			return provider(offset, sink);
		};
		content_provider_resource_releaser_ = resource_releaser;
	}

	Response::~Response()
	{
		if (content_provider_resource_releaser_)
			content_provider_resource_releaser_();
	}

	ssize_t Stream::write(const char* ptr)
	{
		return write(ptr, strlen(ptr));
	}

	ssize_t Stream::write(const std::string& s)
	{
		return write(s.data(), s.size());
	}


	ThreadPool::ThreadPool(size_t n)
	{
		while (n)
		{
			threads_.emplace_back(worker(*this));
			n--;
		}
	}
	void ThreadPool::enqueue(std::function<void()> fn)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		jobs_.push_back(fn);
		cond_.notify_one();
	}

	void ThreadPool::shutdown()
	{
		// Stop all worker threads...
		{
			std::unique_lock<std::mutex> lock(mutex_);
			shutdown_ = true;
		}

		cond_.notify_all();

		// Join...
		for (auto& t : threads_)
		{
			t.join();
		}
	}

	ThreadPool::worker::worker(ThreadPool& pool) : pool_(pool) {}
	void ThreadPool::worker::operator()()
	{
		for (;;)
		{
			std::function<void()> fn;

			{
				std::unique_lock<std::mutex> lock(pool_.mutex_);

				pool_.cond_.wait(lock, [&]
					{ 
						return !pool_.jobs_.empty() || pool_.shutdown_; 
					});

				if (pool_.shutdown_ && pool_.jobs_.empty())
					break;

				fn = std::move(pool_.jobs_.front());
				pool_.jobs_.pop_front();
			}

			if (fn)
				fn();
		}
	}

}
