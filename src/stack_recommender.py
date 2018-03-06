#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
from recommender import RecommendationTask
from stack_aggregator import StackAggregator
from concurrent import futures


class StackRecommender:

    def __init__(self):
        self.recommender_task = None
        self.stack_aggregator_task = None
        self.executor = futures.ThreadPoolExecutor(max_workers=2)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    @asyncio.coroutine
    def recommender_result(self, input_json, persist):
        self.recommender_task = yield from self.loop.run_in_executor(
            self.executor, RecommendationTask().execute, input_json, persist)

    @asyncio.coroutine
    def aggregator_result(self, input_json, persist):
        self.stack_aggregator_task = yield from self.loop.run_in_executor(
            self.executor, StackAggregator().execute, input_json, persist)

    def execute(self, input_json, persist=True):
        try:
            tasks = [self.recommender_result(input_json, persist),
                     self.aggregator_result(input_json, persist)]
            self.loop.run_until_complete(asyncio.gather(*tasks))
            return {
                'status': 'success',
                'recommender': self.recommender_task,
                'stack_aggregator': self.stack_aggregator_task
            }
        except Exception as e:
            return {
                'status': 'StackRecommender Error',
                'external_request_id': input_json.get('external_request_id'),
                'message': str(e)
            }
        finally:
            self.loop.close()
            self.executor._threads.clear()
