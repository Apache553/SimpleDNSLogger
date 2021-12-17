#include "Rpc.h"

SimpleDNSLogger::ObserveHandler::ObserveHandler(DNSLogger::AsyncService* service, grpc::ServerCompletionQueue* cq,
                                                RpcHandler* rpcHandler) : service(service), cq(cq), responder(&ctx),
                                                                          rpcHandler(rpcHandler)
{
	uintptr_t ptr = reinterpret_cast<uintptr_t>(this);
	ctx.AsyncNotifyWhenDone(reinterpret_cast<void*>(ptr | 1));
	expectedCompletion = 1;
}

SimpleDNSLogger::ObserveHandler::~ObserveHandler()
{
}

void SimpleDNSLogger::ObserveHandler::UpdateStatus(bool ok, bool doneFlag)
{
	std::unique_lock lg(mutex);
	if (doneFlag)
	{
		if (status == WaitForWitness)
			if (rpcHandler->CancelObservation(request.expectedname()))
				--expectedCompletion;
		status = Done;
	}
	switch (status)
	{
	case New:
		// start rpc
		if (!rpcHandler->IsRunning())
		{
			// server exited
			delete this;
			return;
		}
		service->RequestObserveDnsQuery(&ctx, &request, &responder, cq, cq, this);
		++expectedCompletion;
		status = Created;
		break;
	case Created:
		// got request
		--expectedCompletion;
		if (!ok)
		{
			// server exiting
			status = Done;
			break;
		}
		status = WaitForWitness;
		rpcHandler->CreateNewObserveHandler();
		if (!request.has_identity() ||
			!rpcHandler->CheckPsk(request.identity().psk()) ||
			request.expectedname().empty() ||
			!rpcHandler->CreateObservation(request.expectedname(),
			                               std::bind(&ObserveHandler::SetResult, this, std::placeholders::_1,
			                                         std::placeholders::_2)))
		{
			status = Done;
			responder.FinishWithError(grpc::Status::CANCELLED, this);
		}
		++expectedCompletion;
		break;
	case WaitForWitness:
		--expectedCompletion;
		status = Witnessed;
	case Witnessed:
		status = Done;
		responder.Finish(result, grpc::Status::OK, this);
		++expectedCompletion;
		break;
	case Done:
		--expectedCompletion;
		if (expectedCompletion == 0)
		{
			lg.release();
			delete this;
		}
		break;
	default:
		assert(false && "unexpected status!");
	}
}

void SimpleDNSLogger::ObserveHandler::SetResult(const std::string& name, const std::string& ip)
{
	result.set_observedname(name);
	result.set_sender(ip);
	grpc::Alarm alarm;
	alarm.Set(cq, std::chrono::system_clock::now(), this);
}

SimpleDNSLogger::RpcHandler::RpcHandler()
{
}

SimpleDNSLogger::RpcHandler::~RpcHandler()
{
	StopServer();
}

void SimpleDNSLogger::RpcHandler::StartServer(const std::string& address, unsigned short port)
{
	grpc::ServerBuilder builder;
	builder.AddListeningPort(address + ":" + std::to_string(port), grpc::InsecureServerCredentials());
	builder.RegisterService(&srvService);
	srvCompleteQueue = builder.AddCompletionQueue();
	srvServer = builder.BuildAndStart();
	running = true;

	srvThread = std::thread([this]()
	{
		CreateNewObserveHandler();
		void* tag;
		bool ok;
		while (srvCompleteQueue->Next(&tag, &ok))
		{
			uintptr_t uptr = reinterpret_cast<uintptr_t>(tag);
			auto ptr = reinterpret_cast<ObserveHandler*>(uptr & ~1);
			ptr->UpdateStatus(ok, uptr & 1);
		}
	});
}

void SimpleDNSLogger::RpcHandler::StopServer()
{
	running = false;
	if (srvServer)
		srvServer->Shutdown();
	if (srvCompleteQueue)
		srvCompleteQueue->Shutdown();
	if (srvThread.joinable())
		srvThread.join();
	srvServer.reset();
	srvCompleteQueue.reset();
}

void SimpleDNSLogger::RpcHandler::CreateNewObserveHandler()
{
	if (!running)return;
	auto ptr = new ObserveHandler(&srvService, srvCompleteQueue.get(), this);
	ptr->UpdateStatus(true, false);
}

void SimpleDNSLogger::RpcHandler::WitnessDnsQuery(const std::string& name, const std::string& ip)
{
	std::unique_lock lg(observedNamesMutex);
	auto it = observedNames.find(name);
	if (it == observedNames.end())
		return;
	auto fn = std::move(it->second);
	observedNames.erase(it);
	lg.unlock();
	fn(name, ip);
}

void SimpleDNSLogger::RpcHandler::AddPsk(const std::string& psk)
{
	authorizedPsk.insert(psk);
}

bool SimpleDNSLogger::RpcHandler::CheckPsk(const std::string& psk)
{
	return authorizedPsk.find(psk) != authorizedPsk.end();
}

bool SimpleDNSLogger::RpcHandler::CreateObservation(const std::string& name, ObserveCallback&& callback)
{
	std::lock_guard lg(observedNamesMutex);
	auto it = observedNames.find(name);
	if (it != observedNames.end())
		return false;
	observedNames.insert(std::make_pair(name, std::move(callback)));
	return true;
}

bool SimpleDNSLogger::RpcHandler::CancelObservation(const std::string& name)
{
	std::lock_guard lg(observedNamesMutex);
	auto it = observedNames.find(name);
	if (it == observedNames.end())
		return false;
	observedNames.erase(it);
	return true;
}
